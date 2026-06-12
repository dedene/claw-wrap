package credentials

import "strings"

// ResolveInput is the neutral credential resolution spec mapped from config at call sites.
type ResolveInput struct {
	Label          string
	Source         string
	Type           string
	AppID          int64
	InstallationID int64
	PrivateKey     string
	APIURL         string
	Permissions    map[string]string
	Repositories   []string
}

// DisplaySource returns a human-readable identifier for logging.
func (in ResolveInput) DisplaySource() string {
	if label := strings.TrimSpace(in.Label); label != "" {
		return label
	}
	if source := strings.TrimSpace(in.Source); source != "" {
		return source
	}
	if strings.TrimSpace(in.Type) == githubAppCredentialType {
		return githubAppDisplaySource(in.AppID, in.InstallationID)
	}
	return ""
}

// Resolve fetches a credential value from either a static source or a dynamic provider.
func Resolve(input ResolveInput, opts ...FetchOption) (string, error) {
	cred, err := ResolveCredential(input, opts...)
	if err != nil {
		return "", err
	}
	return cred.Value, nil
}

// FetchSourceCredentialFunc fetches source-based credentials. Daemon tests override
// this via fetchCredentialFunc while production uses FetchCredential.
var FetchSourceCredentialFunc = func(source string, opts ...FetchOption) (Credential, error) {
	return FetchCredential(source, opts...)
}

// ResolveCredential fetches a credential with expiry metadata.
func ResolveCredential(input ResolveInput, opts ...FetchOption) (Credential, error) {
	typ := strings.TrimSpace(input.Type)
	if typ == "" {
		return FetchSourceCredentialFunc(strings.TrimSpace(input.Source), opts...)
	}
	if typ == githubAppCredentialType {
		return fetchGitHubAppCredential(input, opts...)
	}
	return Credential{}, errUnknownCredentialType(typ)
}
