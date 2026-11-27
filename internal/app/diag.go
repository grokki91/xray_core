package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/grokki91/xray_core/internal/config"
	"github.com/grokki91/xray_core/internal/contract"
	"github.com/grokki91/xray_core/internal/core"
	"github.com/grokki91/xray_core/internal/diag"
	"github.com/grokki91/xray_core/internal/update"
)

// diagTimeout — срок прогона каталога: бюджет docs/operations/diagnostics.md §5. Запись истории
// и экспорта идёт после прогона, под исходным контекстом.
const diagTimeout = 30 * time.Second

// exportDirs — где может лежать файл экспорта: root пишет его, поэтому системные файлы и
// состояние xm исключены закрытым списком, а существующий файл не заменяется.
var exportDirs = []string{"/root/", "/home/", "/tmp/"}

// DiagOptions — `xm diag`: Only — одна категория каталога; Export — абсолютный путь файла
// для отредактированного отчёта.
type DiagOptions struct {
	Only   string
	Export string
}

// Diagnose прогоняет каталог local (или одну категорию) с самого сервера, проводит отчёт
// через редактор, сохраняет в историю и, если задано, экспортирует. Систему не меняет.
// Возвращает документ diag-report — тот же, что в истории и экспорте.
func (a *App) Diagnose(ctx context.Context, o DiagOptions) (contract.Envelope, error) {
	if o.Export != "" && !exportPath(o.Export) {
		return contract.Envelope{}, fmt.Errorf("%w: --export — абсолютный путь нового файла в /root, /home или /tmp, например /root/diag.json", ErrInput)
	}
	if err := a.needRoot(); err != nil {
		return contract.Envelope{}, err
	}
	if o.Export != "" {
		if _, err := a.s.Host.FS().ReadFile(o.Export); !errors.Is(err, diag.ErrNotFound) {
			return contract.Envelope{}, fmt.Errorf("%w: файл %s уже есть или недоступен; экспорт не заменяет файлы", ErrInput, o.Export)
		}
	}
	runCtx, cancel := context.WithTimeout(ctx, diagTimeout)
	defer cancel()
	st, ok, err := a.installed()
	if err != nil {
		return contract.Envelope{}, err
	}
	if !ok {
		return contract.Envelope{}, ErrNotInstalled
	}
	xray, err := a.s.Core.Current(runCtx)
	if err != nil {
		return contract.Envelope{}, err
	}
	e, err := a.localEngine(st.Server.Port, st.Server.Addresses.IPv4 != "", st.Server.Addresses.IPv6 != "", func() (bool, error) { return a.s.Config.Drift(st) })
	if err != nil {
		return contract.Envelope{}, err
	}
	var r diag.Report
	if o.Only == "" {
		r, err = e.Run(runCtx, diag.SetLocal)
	} else {
		r, err = e.RunCategory(runCtx, diag.SetLocal, o.Only)
		if errors.Is(err, diag.ErrUnknownCategory) {
			return contract.Envelope{}, fmt.Errorf("%w: категория %q неизвестна; есть: %s", ErrInput, o.Only, strings.Join(e.Categories(diag.SetLocal), ", "))
		}
	}
	if err != nil {
		return contract.Envelope{}, err
	}
	now := a.s.Now().UTC()
	rep := toContract(r)
	rep.ID = now.Format("20060102T150405Z")
	rep.Vantage = contract.DiagVantage{Kind: "local", ID: "server"}
	rep.Env = contract.DiagEnv{XM: a.s.XM, Xray: string(xray), OS: a.s.Server.OS()}

	h := diag.History{FS: a.s.Host.FS()}
	if rep.ID, err = h.Free(rep.ID); err != nil {
		return contract.Envelope{}, fmt.Errorf("история диагностики: %w", err)
	}
	env, doc, err := a.redactReport(now, rep)
	if err != nil {
		return contract.Envelope{}, err
	}
	if err := h.Save(rep.ID, doc); err != nil {
		return contract.Envelope{}, fmt.Errorf("история диагностики: %w", err)
	}
	if o.Export != "" {
		if err := h.Export(o.Export, doc); err != nil {
			return contract.Envelope{}, fmt.Errorf("экспорт отчёта (отчёт %s сохранён в истории): %w", rep.ID, err)
		}
	}
	return env, nil
}

// redactReport проводит отчёт через редактор (secrets.md §3): возвращает документ для вывода и
// его байты для истории и экспорта — одно и то же.
func (a *App) redactReport(now time.Time, rep contract.DiagReport) (contract.Envelope, []byte, error) {
	tree, err := a.s.Redactor.JSON(rep)
	if err != nil {
		return contract.Envelope{}, nil, fmt.Errorf("редактор отчёта: %w", err)
	}
	b, err := json.Marshal(tree)
	if err != nil {
		return contract.Envelope{}, nil, err
	}
	var clean contract.DiagReport
	if err := json.Unmarshal(b, &clean); err != nil {
		return contract.Envelope{}, nil, err
	}
	env := contract.New(a.s.XM, now, clean)
	var buf bytes.Buffer
	if err := contract.Encode(&buf, env); err != nil {
		return contract.Envelope{}, nil, err
	}
	return env, buf.Bytes(), nil
}

// localEngine собирает каталог local из менеджеров (ADR-0030): порт и семейства — из состояния.
func (a *App) localEngine(port int, v4, v6 bool, drift func() (bool, error)) (*diag.Engine, error) {
	svc := a.s.Server.Service()
	return diag.NewLocal(diag.LocalDeps{
		ControlDeps: diag.ControlDeps{
			Service: svc,
			Net:     svc,
			Port:    func(context.Context) (int, error) { return port, nil },
			Validate: func(ctx context.Context) (bool, error) {
				err := a.s.Core.ValidateCurrent(ctx, config.Path)
				if errors.Is(err, core.ErrConfig) {
					return false, nil
				}
				return err == nil, err
			},
		},
		HostDeps: diag.HostDeps{
			Disk: a.s.Server.Disk,
			Memory: func(ctx context.Context) (int64, int64, error) {
				m, err := a.s.Server.Memory(ctx)
				return m.AvailKiB, m.TotalKiB, err
			},
			OOMKills:    a.s.Server.OOMKills,
			ClockSynced: a.s.Server.ClockSynced,
		},
		Version: func(ctx context.Context) (string, error) {
			v, err := a.s.Core.Current(ctx)
			return string(v), err
		},
		InRange:  update.Verified().Contains,
		Drift:    func(context.Context) (bool, error) { return drift() },
		Families: a.s.Host.Net(),
		Served: func(context.Context) (diag.Families, error) {
			return diag.Families{IPv4: v4, IPv6: v6}, nil
		},
		Firewall: func(ctx context.Context, port int) (string, string, error) {
			fw, err := a.s.Network.Firewall(ctx, port)
			return string(fw.State), fw.Source, err
		},
		Egress: a.s.Host.Net(),
		Routes: a.s.Host.Net(),
	})
}

// toContract переносит отчёт движка в схему diag-report; ID, точку и окружение ставит вызывающий.
func toContract(r diag.Report) contract.DiagReport {
	out := contract.DiagReport{Health: string(r.Health), Observations: []contract.DiagObservation{}, Findings: []contract.DiagFinding{},
		Summary: contract.DiagSummary{OK: r.Summary.OK, Fail: r.Summary.Fail, Skip: r.Summary.Skip, Error: r.Summary.Error}}
	for _, o := range r.Observations {
		out.Observations = append(out.Observations, contract.DiagObservation{Check: o.Check, Target: o.Target, Status: string(o.Status),
			Value: o.Value, Reason: o.Reason, Limits: o.Limits})
	}
	for _, f := range r.Findings {
		out.Findings = append(out.Findings, contract.DiagFinding{Code: f.Code, Class: string(f.Class), Title: f.Title, Evidence: f.Evidence,
			Alternatives: f.Alternatives, Confirm: f.Confirm, Refute: f.Refute, Actions: f.Actions, Impact: string(f.Impact)})
	}
	return out
}

// exportPath — абсолютный очищенный путь файла внутри exportDirs.
func exportPath(p string) bool {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return false
	}
	for _, d := range exportDirs {
		if rest, ok := strings.CutPrefix(p, d); ok && rest != "" && !strings.HasSuffix(rest, "/") {
			return true
		}
	}
	return false
}
