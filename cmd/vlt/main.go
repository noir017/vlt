// Command vlt reads, writes and searches secrets in a Vaultwarden account.
// It is built for non-interactive use: nothing sensitive is accepted on the
// command line, and nothing sensitive is printed unless explicitly asked for.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/noir017/vlt/internal/secret"
	"github.com/noir017/vlt/internal/store"
	"github.com/noir017/vlt/internal/totp"
	"github.com/noir017/vlt/internal/vw"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const (
	exitOK       = 0
	exitError    = 1
	exitUsage    = 2
	exitNotFound = 3
	exitAuth     = 4
	exitNetwork  = 5
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return exitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "get":
		return cmdGet(rest)
	case "set":
		return cmdSet(rest)
	case "ls", "list":
		return listImpl(rest, false)
	case "find":
		return listImpl(rest, true)
	case "rm", "remove":
		return cmdRemove(rest)
	case "mv", "rename":
		return cmdMove(rest)
	case "run":
		return cmdRun(rest)
	case "doctor":
		return cmdDoctor(rest)
	case "lock":
		return cmdLock(rest)
	case "version", "-v", "--version":
		fmt.Printf("vlt %s (%s, %s)\n", version, commit, date)
		return exitOK
	case "help", "-h", "--help":
		usage(os.Stdout)
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "vlt: unknown command %q\n\n", cmd)
		usage(os.Stderr)
		return exitUsage
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `vlt - secrets for agents, via Vaultwarden

  vlt get <name>|--id <id> [--field password|username|totp|totp-secret|uri|notes|name] [--stdout] [--reveal] [--json]
  vlt set <name> [--username U] [--uri U]...
                 [--password-stdin | --password-file F | --generate [--length N]]
                 [--note-stdin | --note-file F] [--type login|note] [--folder F]
  vlt ls [query] [--folder F] [--json]
  vlt find <query> [--json]
  vlt mv <name> <new> [--folder F] [--json]
  vlt rm <name>... [--yes]
  vlt run --env KEY=<name>.<field> [--env ...] -- <command> [args...]
  vlt doctor
  vlt lock

Secrets are read from stdin, a file, or --generate, never from the command
line. Secret fields are masked unless --reveal is given, and are refused when
stdout is a terminal.
`)
}

// ---------------------------------------------------------------- plumbing

type app struct {
	cfg        *secret.Config
	cl         *vw.Client
	vault      *store.Vault
	red        *secret.Redactor
	cache      string
	freshLogin bool
}

func openApp(ctx context.Context, path string) (*app, error) {
	cfg, err := secret.Load(path)
	if err != nil {
		return nil, err
	}
	red := &secret.Redactor{}
	red.Add(cfg.Password)

	cl := vw.New(cfg.Server, cfg.Email, version)
	if err := cl.Prelogin(ctx); err != nil {
		return nil, err
	}

	cache := secret.CachePath()
	var sync *vw.Sync
	freshLogin := false

	if token, ok := secret.LoadCache(cache, cfg.Server, cfg.Email); ok {
		cl.Token = token
		s, err := cl.Sync(ctx)
		switch {
		case err == nil:
			if err := cl.UnlockWithPassword(s.Profile.Key, cfg.Password); err != nil {
				return nil, err
			}
			sync = s
		case isAuthError(err):
			_ = secret.ClearCache(cache)
		default:
			return nil, err
		}
	}

	if sync == nil {
		freshLogin = true
		ttl, err := cl.Login(ctx, cfg.Password)
		if err != nil {
			return nil, err
		}
		if err := secret.SaveCache(cache, cfg.Server, cfg.Email, cl.Token, ttl); err != nil {
			fmt.Fprintf(os.Stderr, "vlt: warning: cannot cache session: %v\n", err)
		}
		if sync, err = cl.Sync(ctx); err != nil {
			return nil, err
		}
		if cl.Key == nil {
			if err := cl.UnlockWithPassword(sync.Profile.Key, cfg.Password); err != nil {
				return nil, err
			}
		}
	}

	vault, err := store.New(sync, cl.Key)
	if err != nil {
		return nil, err
	}
	return &app{cfg: cfg, cl: cl, vault: vault, red: red, cache: cache, freshLogin: freshLogin}, nil
}

func (a *app) fail(err error) int {
	fmt.Fprintf(os.Stderr, "vlt: %s\n", a.red.Clean(err.Error()))
	return classify(err)
}

func classify(err error) int {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return exitNotFound
	case isAuthError(err):
		return exitAuth
	case isNetError(err):
		return exitNetwork
	default:
		return exitError
	}
}

func isAuthError(err error) bool {
	var he *vw.HTTPError
	if errors.As(err, &he) {
		return he.Status == 401 || he.Status == 403
	}
	return false
}

func isNetError(err error) bool {
	var ne *vw.NetError
	return errors.As(err, &ne)
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parseArgs accepts flags and positionals in any order, and keeps everything
// after "--" as positionals (needed by run).
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	head, tail := args, []string(nil)
	for i, a := range args {
		if a == "--" {
			head, tail = args[:i], args[i+1:]
			break
		}
	}
	var pos []string
	for {
		if err := fs.Parse(head); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		pos = append(pos, rest[0])
		head = rest[1:]
	}
	return append(pos, tail...), nil
}

// ---------------------------------------------------------------- get

func cmdGet(args []string) int {
	fs := newFlags("get")
	cfgPath := configFlag(fs)
	id := fs.String("id", "", "look the item up by id instead of name")
	field := fs.String("field", "", "field to print: name, username, password, totp, uri, notes")
	toStdout := fs.Bool("stdout", false, "print the value (defaults to password)")
	reveal := fs.Bool("reveal", false, "allow secret output to a terminal")
	asJSON := fs.Bool("json", false, "JSON output")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return usageError(err)
	}
	if *id == "" && (len(pos) != 1 || strings.TrimSpace(pos[0]) == "") {
		return usageError(errors.New("get needs exactly one item name, or --id"))
	}
	if *id != "" && len(pos) != 0 {
		return usageError(errors.New("use either a name or --id, not both"))
	}
	name := ""
	if len(pos) == 1 {
		name = pos[0]
	}

	a, err := openApp(context.Background(), *cfgPath)
	if err != nil {
		return failPlain(err)
	}
	var item *store.Item
	if *id != "" {
		item, err = a.vault.FindByID(*id)
	} else {
		item, err = a.vault.Find(name)
	}
	if err != nil {
		return a.fail(err)
	}

	f := *field
	if f == "" && *toStdout {
		f = "password"
	}
	if f != "" {
		val, err := itemField(item, f)
		if err != nil {
			return a.fail(err)
		}
		if isSecretField(f) {
			a.red.Add(val)
			if isTTY(os.Stdout) && !*reveal && !*toStdout {
				return usageError(fmt.Errorf("refusing to print %s to a terminal; use --stdout or --reveal", f))
			}
		}
		fmt.Println(val)
		return exitOK
	}

	if *asJSON {
		out := map[string]any{
			"id":       item.ID,
			"name":     item.Name,
			"username": item.Username,
			"uris":     item.URIs,
			"folder":   item.Folder,
			"updated":  item.Updated,
			"type":     item.Type,
		}
		if *reveal {
			out["password"] = item.Password
			out["totp"] = item.TOTP
			out["notes"] = item.Notes
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return exitOK
	}

	fmt.Printf("name:     %s\n", item.Name)
	fmt.Printf("username: %s\n", item.Username)
	if len(item.URIs) > 0 {
		fmt.Printf("uri:      %s\n", strings.Join(item.URIs, ", "))
	}
	if item.Folder != "" {
		fmt.Printf("folder:   %s\n", item.Folder)
	}
	if !item.Updated.IsZero() {
		fmt.Printf("updated:  %s\n", item.Updated.Local().Format("2006-01-02 15:04:05"))
	}
	if item.HasSecret() {
		fmt.Printf("password: <hidden, use --field password --stdout>\n")
	}
	return exitOK
}

// ---------------------------------------------------------------- set

type optString struct {
	set bool
	val string
}

func (o *optString) String() string     { return o.val }
func (o *optString) Set(v string) error { o.set, o.val = true, v; return nil }

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func cmdSet(args []string) int {
	fs := newFlags("set")
	cfgPath := configFlag(fs)
	var username, folder, typ optString
	var uris stringList
	var passwordStdin, generate, noteStdin, totpStdin bool
	var passwordFile, noteFile, totpFile string
	var length int
	fs.Var(&username, "username", "username")
	fs.Var(&uris, "uri", "URI (repeatable)")
	fs.BoolVar(&passwordStdin, "password-stdin", false, "read the password from stdin")
	fs.StringVar(&passwordFile, "password-file", "", "read the password from a file")
	fs.BoolVar(&generate, "generate", false, "generate a random password")
	fs.IntVar(&length, "length", 32, "generated password length")
	fs.BoolVar(&noteStdin, "note-stdin", false, "read notes from stdin")
	fs.StringVar(&noteFile, "note-file", "", "read notes from a file")
	fs.BoolVar(&totpStdin, "totp-stdin", false, "read a TOTP secret from stdin")
	fs.StringVar(&totpFile, "totp-file", "", "read a TOTP secret from a file")
	fs.Var(&typ, "type", "login or note")
	fs.Var(&folder, "folder", "folder (default: agent)")
	asJSON := fs.Bool("json", false, "print the resulting item as JSON")
	pos, perr := parseArgs(fs, args)
	if perr != nil {
		return usageError(perr)
	}
	if len(pos) != 1 || strings.TrimSpace(pos[0]) == "" {
		return usageError(errors.New("set needs exactly one item name"))
	}
	name := pos[0]
	if typ.set && typ.val != "login" && typ.val != "note" {
		return usageError(errors.New("--type must be login or note"))
	}
	sources := 0
	for _, on := range []bool{passwordStdin, passwordFile != "", generate} {
		if on {
			sources++
		}
	}
	if sources > 1 {
		return usageError(errors.New("use only one of --password-stdin, --password-file, --generate"))
	}
	if noteStdin && noteFile != "" {
		return usageError(errors.New("use only one of --note-stdin and --note-file"))
	}
	if totpStdin && totpFile != "" {
		return usageError(errors.New("use only one of --totp-stdin and --totp-file"))
	}
	if totpStdin && isTTY(os.Stdin) {
		return usageError(errors.New("--totp-stdin needs a pipe; stdin is a terminal"))
	}
	stdinUses := 0
	for _, on := range []bool{passwordStdin, noteStdin, totpStdin} {
		if on {
			stdinUses++
		}
	}
	if stdinUses > 1 {
		return usageError(errors.New("only one of --password-stdin, --note-stdin and --totp-stdin can read stdin"))
	}
	if passwordStdin && isTTY(os.Stdin) {
		return usageError(errors.New("--password-stdin needs a pipe; stdin is a terminal"))
	}
	if noteStdin && isTTY(os.Stdin) {
		return usageError(errors.New("--note-stdin needs a pipe; stdin is a terminal"))
	}

	a, err := openApp(context.Background(), *cfgPath)
	if err != nil {
		return failPlain(err)
	}

	var password string
	switch {
	case passwordStdin:
		password, err = readInput(os.Stdin)
	case passwordFile != "":
		password, err = readFile(passwordFile)
	case generate:
		password, err = generatePassword(length)
	}
	if err != nil {
		return usageError(err)
	}
	if password != "" {
		a.red.Add(password)
	}

	var totpSecret string
	if totpStdin || totpFile != "" {
		if totpStdin {
			totpSecret, err = readInput(os.Stdin)
		} else {
			totpSecret, err = readFile(totpFile)
		}
		if err != nil {
			return usageError(err)
		}
		if totpSecret != "" {
			if _, err := totp.Parse(totpSecret); err != nil {
				return usageError(fmt.Errorf("--totp: %w", err))
			}
			a.red.Add(totpSecret)
		}
	}

	var notes string
	switch {
	case noteStdin:
		notes, err = readInput(os.Stdin)
	case noteFile != "":
		notes, err = readFile(noteFile)
	}
	if err != nil {
		return usageError(err)
	}

	passwordSet := passwordStdin || passwordFile != "" || generate
	notesSet := noteStdin || noteFile != ""

	existing, findErr := a.vault.Find(name)
	if findErr != nil && !errors.Is(findErr, store.ErrNotFound) {
		return a.fail(findErr)
	}
	kind := "login"
	if typ.set {
		kind = typ.val
	} else if existing != nil && existing.Type == 2 {
		kind = "note"
	}
	if existing == nil && kind == "login" && !passwordSet {
		return usageError(errors.New("new login item needs --password-stdin, --password-file or --generate"))
	}

	folderName := "agent"
	if folder.set {
		folderName = folder.val
	}
	folderID := ""
	if existing != nil && !folder.set {
		folderID = existing.FolderID
	}
	if folderID == "" {
		folderID, err = ensureFolder(context.Background(), a, folderName)
		if err != nil {
			return a.fail(err)
		}
	}

	if existing == nil {
		body, err := buildNewItem(a, name, kind, username, uris, password, notes, totpSecret, folderID)
		if err != nil {
			return a.fail(err)
		}
		created, err := a.cl.CreateCipher(context.Background(), body)
		if err != nil {
			return a.fail(err)
		}
		if *asJSON {
			printItemJSON(created.ID, name, "created")
		} else {
			fmt.Printf("created %s\n", name)
		}
		return exitOK
	}

	body, err := buildUpdate(a, existing, name, kind, username, uris, password, notes, totpSecret,
		totpStdin || totpFile != "", passwordSet, notesSet, folderID)
	if err != nil {
		return a.fail(err)
	}
	if _, err := a.cl.UpdateCipher(context.Background(), existing.ID, body); err != nil {
		return a.fail(err)
	}
	if *asJSON {
		printItemJSON(existing.ID, name, "updated")
	} else {
		fmt.Printf("updated %s\n", name)
	}
	return exitOK
}

func buildNewItem(a *app, name, kind string, username optString, uris []string, password, notes, totpSecret, folderID string) (map[string]any, error) {
	encName, err := a.cl.Key.Encrypt([]byte(name))
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"type":           itemType(kind),
		"name":           encName,
		"favorite":       false,
		"reprompt":       0,
		"organizationId": nil,
		"encryptedFor":   a.vault.UID,
	}
	if folderID != "" {
		body["folderId"] = folderID
	}
	if notes != "" {
		enc, err := a.cl.Key.Encrypt([]byte(notes))
		if err != nil {
			return nil, err
		}
		body["notes"] = enc
	}
	if kind == "note" {
		body["secureNote"] = map[string]any{"type": 0}
		return body, nil
	}
	login := map[string]any{
		"uris":     uriList(uris),
		"username": nil,
		"password": nil,
		"totp":     nil,
	}
	if username.set && username.val != "" {
		enc, err := a.cl.Key.Encrypt([]byte(username.val))
		if err != nil {
			return nil, err
		}
		login["username"] = enc
	}
	if password != "" {
		enc, err := a.cl.Key.Encrypt([]byte(password))
		if err != nil {
			return nil, err
		}
		login["password"] = enc
	}
	if totpSecret != "" {
		enc, err := a.cl.Key.Encrypt([]byte(totpSecret))
		if err != nil {
			return nil, err
		}
		login["totp"] = enc
	}
	body["login"] = login
	return body, nil
}

func buildUpdate(a *app, item *store.Item, name, kind string, username optString, uris []string, password, notes, totpSecret string, totpSet, passwordSet, notesSet bool, folderID string) (map[string]any, error) {
	raw, err := store.CloneRaw(item.Raw)
	if err != nil {
		return nil, err
	}
	encName, err := a.cl.Key.Encrypt([]byte(name))
	if err != nil {
		return nil, err
	}
	raw["name"] = encName
	raw["type"] = itemType(kind)
	raw["encryptedFor"] = a.vault.UID
	if folderID != "" {
		raw["folderId"] = folderID
	}
	if notesSet {
		if notes == "" {
			raw["notes"] = nil
		} else {
			enc, err := a.cl.Key.Encrypt([]byte(notes))
			if err != nil {
				return nil, err
			}
			raw["notes"] = enc
		}
	}
	if kind == "note" {
		delete(raw, "login")
		return raw, nil
	}
	login, ok := raw["login"].(map[string]any)
	if !ok {
		login = map[string]any{}
		raw["login"] = login
	}
	if username.set {
		if username.val == "" {
			login["username"] = nil
		} else {
			enc, err := a.cl.Key.Encrypt([]byte(username.val))
			if err != nil {
				return nil, err
			}
			login["username"] = enc
		}
	}
	if len(uris) > 0 {
		login["uris"] = uriList(uris)
	}
	if passwordSet {
		if password == "" {
			login["password"] = nil
		} else {
			enc, err := a.cl.Key.Encrypt([]byte(password))
			if err != nil {
				return nil, err
			}
			login["password"] = enc
		}
	}
	if totpSet {
		if totpSecret == "" {
			login["totp"] = nil
		} else {
			enc, err := a.cl.Key.Encrypt([]byte(totpSecret))
			if err != nil {
				return nil, err
			}
			login["totp"] = enc
		}
	}
	return raw, nil
}

func printItemJSON(id, name, action string) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]string{"id": id, "name": name, "action": action})
}

func itemType(t string) int {
	if t == "note" {
		return 2
	}
	return 1
}

func uriList(uris []string) []map[string]string {
	out := make([]map[string]string, 0, len(uris))
	for _, u := range uris {
		out = append(out, map[string]string{"uri": u})
	}
	return out
}

func ensureFolder(ctx context.Context, a *app, name string) (string, error) {
	if id, missing := a.vault.FolderID(name); !missing {
		return id, nil
	}
	enc, err := a.cl.Key.Encrypt([]byte(name))
	if err != nil {
		return "", err
	}
	return a.cl.CreateFolder(ctx, enc)
}

// ---------------------------------------------------------------- list

func listImpl(args []string, requireQuery bool) int {
	fs := newFlags("ls")
	cfgPath := configFlag(fs)
	asJSON := fs.Bool("json", false, "JSON output")
	folder := fs.String("folder", "", "only items in this folder")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return usageError(err)
	}
	query := strings.Join(pos, " ")
	if requireQuery && query == "" {
		return usageError(errors.New("find needs a query"))
	}

	a, err := openApp(context.Background(), *cfgPath)
	if err != nil {
		return failPlain(err)
	}
	items := a.vault.Search(query)
	if *folder != "" {
		var filtered []*store.Item
		for _, it := range items {
			if it.Folder == *folder {
				filtered = append(filtered, it)
			}
		}
		items = filtered
	}
	if *asJSON {
		out := make([]map[string]any, 0, len(items))
		for _, it := range items {
			out = append(out, map[string]any{
				"id":       it.ID,
				"name":     it.Name,
				"username": it.Username,
				"uris":     it.URIs,
				"folder":   it.Folder,
				"updated":  it.Updated,
				"type":     it.Type,
			})
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return exitOK
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tUSERNAME\tURI\tUPDATED")
	for _, it := range items {
		uri := ""
		if len(it.URIs) > 0 {
			uri = it.URIs[0]
		}
		updated := ""
		if !it.Updated.IsZero() {
			updated = it.Updated.Local().Format("2006-01-02")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", it.Name, it.Username, uri, updated)
	}
	_ = w.Flush()
	return exitOK
}

// ---------------------------------------------------------------- rm

func cmdRemove(args []string) int {
	fs := newFlags("rm")
	cfgPath := configFlag(fs)
	yes := fs.Bool("yes", false, "do not ask")
	id := fs.String("id", "", "delete by id instead of name")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return usageError(err)
	}
	if *id != "" && len(pos) != 0 {
		return usageError(errors.New("use either names or --id, not both"))
	}
	if *id == "" && len(pos) == 0 {
		return usageError(errors.New("rm needs at least one item name, or --id"))
	}
	for _, name := range pos {
		if strings.TrimSpace(name) == "" {
			return usageError(errors.New("empty item name"))
		}
	}

	a, err := openApp(context.Background(), *cfgPath)
	if err != nil {
		return failPlain(err)
	}
	var targets []*store.Item
	if *id != "" {
		item, err := a.vault.FindByID(*id)
		if err != nil {
			return a.fail(err)
		}
		targets = append(targets, item)
	} else {
		for _, name := range pos {
			item, err := a.vault.Find(name)
			if err != nil {
				return a.fail(err)
			}
			targets = append(targets, item)
		}
	}
	if !*yes {
		if !isTTY(os.Stdin) || !confirmed("delete %d item(s)?", len(targets)) {
			return usageError(errors.New("refusing to delete without --yes"))
		}
	}
	for _, item := range targets {
		if err := a.cl.DeleteCipher(context.Background(), item.ID); err != nil {
			return a.fail(err)
		}
		fmt.Printf("deleted %s\n", item.Name)
	}
	return exitOK
}

// ---------------------------------------------------------------- mv

func cmdMove(args []string) int {
	fs := newFlags("mv")
	cfgPath := configFlag(fs)
	id := fs.String("id", "", "rename by id instead of name")
	var folder optString
	fs.Var(&folder, "folder", "move to this folder")
	asJSON := fs.Bool("json", false, "JSON output")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return usageError(err)
	}
	if *id == "" && len(pos) != 2 {
		return usageError(errors.New("mv needs <old> <new>, or --id <id> <new>"))
	}
	if *id != "" && len(pos) != 1 {
		return usageError(errors.New("mv --id needs exactly one new name"))
	}
	if *id == "" && strings.TrimSpace(pos[0]) == "" {
		return usageError(errors.New("empty item name"))
	}
	newName := pos[len(pos)-1]
	if strings.TrimSpace(newName) == "" {
		return usageError(errors.New("new name must not be empty"))
	}

	a, err := openApp(context.Background(), *cfgPath)
	if err != nil {
		return failPlain(err)
	}
	var item *store.Item
	if *id != "" {
		item, err = a.vault.FindByID(*id)
	} else {
		item, err = a.vault.Find(pos[0])
	}
	if err != nil {
		return a.fail(err)
	}
	if item.Name != newName {
		if other, err := a.vault.Find(newName); err == nil && other.ID != item.ID {
			return usageError(fmt.Errorf("an item named %q already exists", newName))
		}
	}

	raw, err := store.CloneRaw(item.Raw)
	if err != nil {
		return a.fail(err)
	}
	enc, err := a.cl.Key.Encrypt([]byte(newName))
	if err != nil {
		return a.fail(err)
	}
	raw["name"] = enc
	raw["encryptedFor"] = a.vault.UID
	if folder.set {
		fid, err := ensureFolder(context.Background(), a, folder.val)
		if err != nil {
			return a.fail(err)
		}
		raw["folderId"] = fid
	}
	if _, err := a.cl.UpdateCipher(context.Background(), item.ID, raw); err != nil {
		return a.fail(err)
	}
	if *asJSON {
		printItemJSON(item.ID, newName, "renamed")
	} else {
		fmt.Printf("renamed %s -> %s\n", item.Name, newName)
	}
	return exitOK
}

// ---------------------------------------------------------------- run

func cmdRun(args []string) int {
	fs := newFlags("run")
	cfgPath := configFlag(fs)
	var envs stringList
	fs.Var(&envs, "env", "KEY=<name>.<field> (repeatable)")
	cmdArgs, err := parseArgs(fs, args)
	if err != nil {
		return usageError(err)
	}
	if len(cmdArgs) == 0 {
		return usageError(errors.New("run needs a command after --"))
	}
	a, err := openApp(context.Background(), *cfgPath)
	if err != nil {
		return failPlain(err)
	}
	extra := make([]string, 0, len(envs))
	for _, spec := range envs {
		key, ref, ok := strings.Cut(spec, "=")
		if !ok || key == "" || ref == "" {
			return usageError(fmt.Errorf("invalid --env %q; want KEY=<name>.<field>", spec))
		}
		name, field, ok := splitRef(ref)
		if !ok {
			return usageError(fmt.Errorf("invalid --env %q; want KEY=<name>.<field>", spec))
		}
		item, err := a.vault.Find(name)
		if err != nil {
			return a.fail(err)
		}
		val, err := itemField(item, field)
		if err != nil {
			return a.fail(err)
		}
		a.red.Add(val)
		extra = append(extra, key+"="+val)
	}
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = append(os.Environ(), extra...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		return a.fail(err)
	}
	return exitOK
}

func splitRef(ref string) (name, field string, ok bool) {
	i := strings.LastIndex(ref, ".")
	if i < 0 {
		// "name" is shorthand for "name.password".
		if ref == "" {
			return "", "", false
		}
		return ref, "password", true
	}
	if i == 0 || i == len(ref)-1 {
		return "", "", false
	}
	return ref[:i], ref[i+1:], true
}

// ---------------------------------------------------------------- doctor / lock

func cmdDoctor(args []string) int {
	fs := newFlags("doctor")
	cfgPath := configFlag(fs)
	if err := fs.Parse(args); err != nil {
		return usageError(err)
	}
	a, err := openApp(context.Background(), *cfgPath)
	if err != nil {
		return failPlain(err)
	}
	fmt.Printf("config: %s (ok)\n", a.cfg.Path)
	serverCfg, err := a.cl.Config(context.Background())
	if err != nil {
		fmt.Printf("server: %s (cannot read /api/config: %v)\n", a.cfg.Server, err)
	} else {
		fmt.Printf("server: %s (%s %s)\n", a.cfg.Server, serverCfg.Server.Name, serverCfg.Version)
	}
	fmt.Printf("auth:   %s (user %s)\n", a.cfg.Email, a.vault.UID)
	switch {
	case a.freshLogin:
		fmt.Printf("cache:  none (logged in just now)\n")
	default:
		fmt.Printf("cache:  %s (hit)\n", a.cache)
	}
	fmt.Printf("items:  %d, folders: %d\n", len(a.vault.Items), len(a.vault.Folders))
	return exitOK
}

func cmdLock(args []string) int {
	fs := newFlags("lock")
	if err := fs.Parse(args); err != nil {
		return usageError(err)
	}
	if err := secret.ClearCache(secret.CachePath()); err != nil {
		return failPlain(err)
	}
	fmt.Println("token cache cleared")
	return exitOK
}

// ---------------------------------------------------------------- helpers

func configFlag(fs *flag.FlagSet) *string {
	return fs.String("config", "", "configuration file (default: ~/.secrets/vlt.env)")
}

func itemField(it *store.Item, f string) (string, error) {
	switch f {
	case "name":
		return it.Name, nil
	case "username":
		return it.Username, nil
	case "password":
		return it.Password, nil
	case "notes", "note":
		return it.Notes, nil
	case "uri":
		if len(it.URIs) == 0 {
			return "", nil
		}
		return it.URIs[0], nil
	case "totp-secret":
		if it.TOTP == "" {
			return "", errors.New("item has no TOTP secret")
		}
		return it.TOTP, nil
	case "totp", "otp":
		if it.TOTP == "" {
			return "", errors.New("item has no TOTP secret")
		}
		cfg, err := totp.Parse(it.TOTP)
		if err != nil {
			return "", err
		}
		return cfg.Code(time.Now()), nil
	default:
		return "", fmt.Errorf("unknown field %q; use name, username, password, totp, totp-secret, uri or notes", f)
	}
}

func isSecretField(f string) bool {
	switch f {
	case "password", "totp", "otp", "totp-secret", "notes", "note":
		return true
	}
	return false
}

func readInput(r io.Reader) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, 1<<20))
	if err != nil {
		return "", err
	}
	return trimNewline(string(b)), nil
}

func readFile(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s is readable by group or others; chmod 600 it first", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return trimNewline(string(b)), nil
}

func trimNewline(s string) string {
	s = strings.TrimSuffix(s, "\n")
	return strings.TrimSuffix(s, "\r")
}

func generatePassword(n int) (string, error) {
	if n < 12 {
		return "", errors.New("--length must be at least 12")
	}
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := make([]byte, 0, n)
	buf := make([]byte, n)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if int(b) < 256-(256%len(alphabet)) {
				out = append(out, alphabet[int(b)%len(alphabet)])
				if len(out) == n {
					break
				}
			}
		}
	}
	return string(out), nil
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func confirmed(format string, args ...any) bool {
	fmt.Printf(format+" [y/N] ", args...)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes"
}

func usageError(err error) int {
	fmt.Fprintf(os.Stderr, "vlt: %v\n", err)
	return exitUsage
}

func failPlain(err error) int {
	fmt.Fprintf(os.Stderr, "vlt: %v\n", err)
	return classify(err)
}
