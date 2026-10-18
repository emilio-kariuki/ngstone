package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"ngstone/internal/credentials"
)

const defaultCredentialTTL = 24 * time.Hour

func cmdCredentials(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(os.Stderr, "usage: ngstone credentials <issue|list|revoke> [options]")
		return 2
	}
	switch args[0] {
	case "issue":
		return cmdCredentialIssue(args[1:])
	case "list":
		return cmdCredentialList(args[1:])
	case "revoke":
		return cmdCredentialRevoke(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "ngstone: unknown credentials subcommand %q\n", args[0])
		return 2
	}
}

func credentialFileFlag(fs *flag.FlagSet) *string {
	return fs.String("file", os.Getenv("NGSTONE_CREDENTIALS_FILE"), "credential file (defaults to NGSTONE_CREDENTIALS_FILE)")
}

func requireCredentialFile(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("credential file is required; pass --file or set NGSTONE_CREDENTIALS_FILE")
	}
	return path, nil
}

func cmdCredentialIssue(args []string) int {
	fs := flag.NewFlagSet("credentials issue", flag.ContinueOnError)
	fileFlag := credentialFileFlag(fs)
	kind := fs.String("kind", credentials.KindHTTP, "credential kind: http, tcp, or preview")
	subdomain := fs.String("subdomain", "", "exact HTTP subdomain this credential may bind")
	remotePort := fs.Int("remote-port", 0, "exact TCP port this credential may bind")
	ttl := fs.Duration("ttl", defaultCredentialTTL, "credential lifetime, up to 720h")
	jsonOutput := fs.Bool("json", false, "print the issued credential as JSON")
	positionals, err := parsePermissive(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 0 {
		fmt.Fprintln(os.Stderr, "usage: ngstone credentials issue --subdomain demo [--ttl 24h] [--file path]")
		return 2
	}
	path, err := requireCredentialFile(*fileFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ngstone: "+err.Error())
		return 2
	}
	store, err := credentials.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: opening credential file: %v\n", err)
		return 1
	}
	issued, err := store.Issue(credentials.Spec{
		Kind:       *kind,
		Subdomain:  *subdomain,
		RemotePort: *remotePort,
	}, *ttl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: issuing credential: %v\n", err)
		return 2
	}
	if *jsonOutput {
		output := struct {
			credentials.Credential
			Token string `json:"token"`
		}{Credential: issued.Credential, Token: issued.Token}
		if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
			fmt.Fprintf(os.Stderr, "ngstone: writing credential: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Printf("credential %s issued\n", issued.Credential.ID)
	fmt.Printf("kind: %s\n", issued.Credential.Kind)
	if issued.Credential.Subdomain != "" {
		fmt.Printf("subdomain: %s\n", issued.Credential.Subdomain)
	}
	if issued.Credential.RemotePort != 0 {
		fmt.Printf("remote port: %d\n", issued.Credential.RemotePort)
	}
	fmt.Printf("expires: %s\n", issued.Credential.ExpiresAt.UTC().Format(time.RFC3339))
	fmt.Printf("token: %s\n", issued.Token)
	fmt.Fprintln(os.Stderr, "save this token now; it cannot be recovered from the credential file")
	return 0
}

func cmdCredentialList(args []string) int {
	fs := flag.NewFlagSet("credentials list", flag.ContinueOnError)
	fileFlag := credentialFileFlag(fs)
	jsonOutput := fs.Bool("json", false, "print credentials as JSON")
	positionals, err := parsePermissive(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 0 {
		fmt.Fprintln(os.Stderr, "usage: ngstone credentials list [--json] [--file path]")
		return 2
	}
	path, err := requireCredentialFile(*fileFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ngstone: "+err.Error())
		return 2
	}
	store, err := credentials.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: opening credential file: %v\n", err)
		return 1
	}
	list, err := store.List()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: listing credentials: %v\n", err)
		return 1
	}
	if *jsonOutput {
		if err := json.NewEncoder(os.Stdout).Encode(list); err != nil {
			fmt.Fprintf(os.Stderr, "ngstone: writing credentials: %v\n", err)
			return 1
		}
		return 0
	}
	if len(list) == 0 {
		fmt.Println("no credentials")
		return 0
	}
	for _, credential := range list {
		state := "active"
		if credential.RevokedAt != nil {
			state = "revoked"
		} else if !time.Now().Before(credential.ExpiresAt) {
			state = "expired"
		}
		fmt.Printf("%s\t%s\t%s\t%s\n", credential.ID, credential.Kind, state, credential.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return 0
}

func cmdCredentialRevoke(args []string) int {
	fs := flag.NewFlagSet("credentials revoke", flag.ContinueOnError)
	fileFlag := credentialFileFlag(fs)
	positionals, err := parsePermissive(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 1 {
		fmt.Fprintln(os.Stderr, "usage: ngstone credentials revoke <credential-id> [--file path]")
		return 2
	}
	path, err := requireCredentialFile(*fileFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ngstone: "+err.Error())
		return 2
	}
	store, err := credentials.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: opening credential file: %v\n", err)
		return 1
	}
	if err := store.Revoke(positionals[0]); err != nil {
		if errors.Is(err, credentials.ErrNotFound) {
			fmt.Fprintf(os.Stderr, "ngstone: credential %q was not found\n", positionals[0])
			return 2
		}
		fmt.Fprintf(os.Stderr, "ngstone: revoking credential: %v\n", err)
		return 1
	}
	fmt.Printf("credential %s revoked\n", positionals[0])
	return 0
}
