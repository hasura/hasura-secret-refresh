package hashicorp_vault

import (
	"context"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/rs/zerolog"
)

// vaultClient owns a Vault *api.Client and a background lifecycle goroutine
// that keeps the client token renewed. All FetchSecret-style callers share
// the same client.
type vaultClient struct {
	api    *api.Client
	cfg    VaultConfig
	logger zerolog.Logger

	mu sync.RWMutex
}

// newAuthenticatedClient logs in once and then starts the background token
// lifecycle manager. The returned client is immediately usable.
func newAuthenticatedClient(cfg VaultConfig, logger zerolog.Logger) (*vaultClient, error) {
	client, err := newVaultClient(cfg)
	if err != nil {
		return nil, err
	}

	authInfo, err := login(context.Background(), client, cfg, logger)
	if err != nil {
		return nil, err
	}

	vc := &vaultClient{
		api:    client,
		cfg:    cfg,
		logger: logger,
	}

	go vc.manageTokenLifecycle(authInfo)

	return vc, nil
}

// client returns the wrapped api.Client. It exists so callers don't reach
// straight into the struct field while a re-login might be swapping it.
func (v *vaultClient) client() *api.Client {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.api
}

// manageTokenLifecycle blocks forever, renewing the current token via a
// LifetimeWatcher and re-logging-in if the watcher dies. It is intended to
// run as a goroutine for the lifetime of the process.
func (v *vaultClient) manageTokenLifecycle(authInfo *api.Secret) {
	for {
		if authInfo == nil || authInfo.Auth == nil {
			v.logger.Warn().Msg("hashicorp_vault: empty auth info, re-logging in")
			authInfo = v.reLogin()
			continue
		}

		if !authInfo.Auth.Renewable {
			v.logger.Warn().Msg("hashicorp_vault: token is not renewable, sleeping until just before TTL then re-logging in")
			lease := time.Duration(authInfo.Auth.LeaseDuration) * time.Second
			if lease <= 0 {
				lease = 5 * time.Minute
			}
			// Sleep until ~80% of TTL to leave time for re-login.
			time.Sleep(lease * 4 / 5)
			authInfo = v.reLogin()
			continue
		}

		watcher, err := v.api.NewLifetimeWatcher(&api.LifetimeWatcherInput{
			Secret: authInfo,
		})
		if err != nil {
			v.logger.Err(err).Msg("hashicorp_vault: failed to start lifetime watcher, will retry after delay")
			time.Sleep(10 * time.Second)
			authInfo = v.reLogin()
			continue
		}

		go watcher.Start()

		v.watchOnce(watcher)
		watcher.Stop()

		// Watcher exited; we must re-login to obtain a fresh token+secret.
		authInfo = v.reLogin()
	}
}

// watchOnce blocks until the LifetimeWatcher channel signals the token has
// either reached the end of its renewable life (DoneCh) or has been renewed
// (RenewCh). For renew, it logs and keeps looping; for done, it returns so
// the outer loop can re-login.
func (v *vaultClient) watchOnce(watcher *api.LifetimeWatcher) {
	for {
		select {
		case err := <-watcher.DoneCh():
			if err != nil {
				v.logger.Err(err).Msg("hashicorp_vault: token watcher exited with error; will re-login")
			} else {
				v.logger.Info().Msg("hashicorp_vault: token reached end of lifetime; will re-login")
			}
			return
		case renewal := <-watcher.RenewCh():
			if renewal != nil && renewal.Secret != nil && renewal.Secret.Auth != nil {
				v.logger.Debug().
					Int("lease_duration_seconds", renewal.Secret.Auth.LeaseDuration).
					Msg("hashicorp_vault: token renewed")
			} else {
				v.logger.Debug().Msg("hashicorp_vault: token renewed")
			}
		}
	}
}

// reLogin re-authenticates and swaps the underlying api.Client's token in
// place. It retries until success.
func (v *vaultClient) reLogin() *api.Secret {
	backoff := 1 * time.Second
	const maxBackoff = 60 * time.Second

	for {
		authInfo, err := login(context.Background(), v.api, v.cfg, v.logger)
		if err == nil {
			return authInfo
		}
		v.logger.Err(err).Dur("retry_in", backoff).Msg("hashicorp_vault: re-login failed; will retry")
		time.Sleep(backoff)
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}
