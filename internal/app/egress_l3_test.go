//go:build l3

package app

import (
	"encoding/json"
	"net"
	"runtime"
	"testing"

	"github.com/grokki91/xray_core/internal/platform/xraytest"
)

// L3, задача A8 (ADR-0038): правило finalRules по порту из отрисовки рвёт соединение клиента на
// живом трафике. Порт 25 без root не занять, поэтому номер в отрисованном правиле подменяется
// на порт слушателя; что в отрисовке стоит именно tcp:25, доказывает L2
// TestRenderRestrictsClientEgress. Слушатель на петле, поэтому сразу за правилом порта — allow для
// 127.0.0.1, иначе соединение раньше остановил бы запрет частных адресов. Контроль: та же
// конфигурация без правила порта пропускает запрос — значит, отказ даёт правило порта.
func TestL3BlockedPortNotReached(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("архив Xray-linux-64 — только для хоста amd64")
	}
	for _, v := range xraytest.Versions() {
		t.Run(v, func(t *testing.T) {
			st := newEgressStand(t, v)
			target := net.JoinHostPort("127.0.0.1", st.svcPort)
			if !st.run(portRule(t, st.cfg, st.svcPort, false), target) {
				t.Fatal("контроль: без правила порта запрос не дошёл — тоннель не работает")
			}
			if st.run(portRule(t, st.cfg, st.svcPort, true), target) {
				t.Errorf("запрос через тоннель на запрещённый порт дошёл до слушателя")
			}
		})
	}
}

// portRule берёт отрисованное правило tcp:25 из finalRules freedom и, если keep, ставит в нём
// порт слушателя, иначе убирает его; за ним — allow для петли.
func portRule(t *testing.T, cfg []byte, port string, keep bool) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(cfg, &doc); err != nil {
		t.Fatal(err)
	}
	s := doc["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)
	var rules []any
	found := false
	for _, r := range s["finalRules"].([]any) {
		m := r.(map[string]any)
		if m["port"] == "25" && m["network"] == "tcp" && m["action"] == "block" {
			found = true
			if keep {
				m["port"] = port
				rules = append(rules, m)
			}
			rules = append(rules, map[string]any{"action": "allow", "ip": []string{"127.0.0.1/32"}})
			continue
		}
		rules = append(rules, m)
	}
	if !found {
		t.Fatal("в отрисовке нет правила tcp:25")
	}
	s["finalRules"] = rules
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
