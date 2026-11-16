package platform

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
)

// ServiceUser — единственный пользователь, которого создаёт xm (docs/security/policy.md §3).
const ServiceUser = "xray"

// useradd — программа создания системного пользователя; путь — в закрытом списке programs.
const useradd = "useradd"

func checkName(name string) error {
	if name != ServiceUser {
		return fmt.Errorf("%w: %q", ErrName, name)
	}
	return nil
}

func lookup(name string) (Owner, bool, error) {
	u, err := user.Lookup(name)
	var unknown user.UnknownUserError
	if errors.As(err, &unknown) {
		return Owner{}, false, nil
	}
	if err != nil {
		return Owner{}, false, fmt.Errorf("пользователь %s: %w", name, err)
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return Owner{}, false, fmt.Errorf("пользователь %s: нечисловые идентификаторы", name)
	}
	return Owner{UID: uid, GID: gid}, true, nil
}

type realUsers struct{ r *Real }

func (realUsers) Effective() Owner { return Owner{UID: os.Geteuid(), GID: os.Getegid()} }

func (u realUsers) Ensure(ctx context.Context, name string) (Owner, error) {
	if err := checkName(name); err != nil {
		return Owner{}, err
	}
	if _, ok := ctx.Deadline(); !ok {
		return Owner{}, ErrDeadline
	}
	if o, ok, err := lookup(name); err != nil || ok {
		return o, err
	}
	res, err := u.r.Exec(ctx, Command{Program: useradd, Args: []string{
		"--system", "--user-group", "--no-create-home", "--shell", "/usr/sbin/nologin", name}})
	if err != nil {
		return Owner{}, err
	}
	if res.ExitCode != 0 {
		return Owner{}, fmt.Errorf("useradd %s: код %d", name, res.ExitCode)
	}
	o, ok, err := lookup(name)
	if err != nil {
		return Owner{}, err
	}
	if !ok {
		return Owner{}, fmt.Errorf("пользователь %s не появился после useradd", name)
	}
	return o, nil
}

// fakeUsers — поддельные пользователи: идентификаторы выдаются по порядку с 990; процесс xm —
// root, пока тест не назначил другого (SetEffective).
type fakeUsers struct{ f *Fake }

func (u fakeUsers) Effective() Owner {
	u.f.mu.Lock()
	defer u.f.mu.Unlock()
	return u.f.effective
}

// SetEffective назначает владельца процесса xm, которого вернёт Users().Effective().
func (f *Fake) SetEffective(o Owner) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.effective = o
}

func (u fakeUsers) Ensure(ctx context.Context, name string) (Owner, error) {
	if err := checkName(name); err != nil {
		return Owner{}, err
	}
	if _, ok := ctx.Deadline(); !ok {
		return Owner{}, ErrDeadline
	}
	u.f.mu.Lock()
	defer u.f.mu.Unlock()
	if o, ok := u.f.users[name]; ok {
		return o, nil
	}
	id := 990 + len(u.f.users)
	o := Owner{UID: id, GID: id}
	u.f.users[name] = o
	u.f.calls = append(u.f.calls, Call{Op: "user", Path: name})
	return o, nil
}
