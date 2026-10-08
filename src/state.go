package main

import (
	"crypto/ecdsa"
	"errors"
	"sync"
	"time"

	"crypto/mldsa"
	"github.com/JLugagne/egauth/oauth"
)

type Device struct {
	UpstreamNamespace, Sub, Email, Provider, UpstreamSub, JTI string
	DeviceName, IdentityName                                  string
	PublicKey                                                 *ecdsa.PublicKey
	MLDSA65PublicKey                                          *mldsa.PublicKey
	Exp                                                       time.Time
}

type Login struct {
	ID, ClientID, RedirectURI, OAuthState, Nonce, Challenge, PKCE, Scope string
	Created, Expires                                                     time.Time
	BrowserSecret                                                        string
	State                                                                string
	MobileCodeAttempts                                                   int
	Device                                                               *Device
	Code                                                                 string
}

type Enrollment struct {
	ID               string
	PublicKey        *ecdsa.PublicKey
	MLDSA65PublicKey *mldsa.PublicKey
	Name             string
	ReturnURI        string
	Created, Expires time.Time
	State, Email     string
	Payload          string
	Device           *Device
}

type AuthCode struct {
	Value                                                                        string
	ClientID, RedirectURI, CodeChallenge, Sub, Email, IdentityName, Nonce, Scope string
	Expires                                                                      time.Time
}

type MobileCode struct {
	Value     string
	Device    *Device
	CreatedAt time.Time
	ExpiresAt time.Time
}

type WatchCapability struct {
	Token     string
	Device    *Device
	ExpiresAt time.Time
}

type UpstreamState struct {
	Value        string
	EnrollmentID string
	ProviderID   string
	Nonce        string
	Verifier     string
	ExpiresAt    time.Time
}

const (
	maxActiveEnrollments    = 10000
	maxActiveLogins         = 10000
	maxUpstreamStates       = 10000
	maxMobileCodeAttempts   = 5
	watchCapabilityLifetime = 30 * 24 * time.Hour
)

func copyDevice(device *Device) *Device {
	if device == nil {
		return nil
	}

	copy := *device
	return &copy
}

func (s *Store) loginSnapshot(id string) (Login, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	login, ok := s.loginState[id]
	if !ok || login == nil {
		return Login{}, false
	}

	snapshot := *login
	snapshot.Device = copyDevice(login.Device)
	return snapshot, true
}

func (s *Store) enrollmentSnapshot(id string) (Enrollment, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	enrollment, ok := s.enrollmentState[id]
	if !ok || enrollment == nil {
		return Enrollment{}, false
	}

	snapshot := *enrollment
	snapshot.Device = copyDevice(enrollment.Device)
	return snapshot, true
}

func (s *Store) approveLoginWithMobileCode(id, code string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	login := s.loginState[id]
	if login == nil {
		return errors.New("login not found")
	}

	if expireLoginIfNeeded(login, now) {
		return errors.New("login expired")
	}

	if login.State != "pending" {
		return errors.New("login is not pending")
	}

	mobile := s.mobileCodes[code]
	if mobile == nil || !now.Before(mobile.ExpiresAt) {
		login.MobileCodeAttempts++
		if login.MobileCodeAttempts >= maxMobileCodeAttempts {
			login.State = "expired"
		}

		return errors.New("mobile code expired")
	}

	delete(s.mobileCodes, code)
	login.Device = mobile.Device
	login.State = "approved"

	return nil
}

func (s *Store) verifyEnrollment(id string, device *Device, email, payload string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	enrollment := s.enrollmentState[id]
	if enrollment == nil {
		return errors.New("enrollment not found")
	}

	if !now.Before(enrollment.Expires) {
		enrollment.State = "expired"
		return errors.New("enrollment expired")
	}

	if enrollment.State != "pending" {
		return errors.New("enrollment is not pending")
	}

	enrollment.State = "verified"
	enrollment.Email = email
	enrollment.Payload = payload
	enrollment.Device = device

	return nil
}

func (s *Store) expireEnrollmentIfNeeded(enrollment *Enrollment, now time.Time) {
	if enrollment != nil && !now.Before(enrollment.Expires) && enrollment.State != "complete" {
		enrollment.State = "expired"
	}
}

func (s *Store) createMobileCode(device *Device, expires time.Time, groups int) (string, error) {
	for range 5 {
		code, err := mobileCode(groups)
		if err != nil {
			return "", err
		}

		normalized := normalizeMobileCode(code)
		s.mu.Lock()
		existing := s.mobileCodes[normalized]
		if existing == nil || !time.Now().Before(existing.ExpiresAt) {
			s.mobileCodes[normalized] = &MobileCode{Value: code, Device: device, CreatedAt: time.Now(), ExpiresAt: expires}
			s.mu.Unlock()
			return code, nil
		}
		s.mu.Unlock()
	}

	return "", errors.New("could not allocate unique login code")
}

func (s *Store) completeEnrollment(id string, signatures map[string]string, cfg Config, now time.Time) (string, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	enrollment := s.enrollmentState[id]
	if enrollment == nil {
		return "", time.Time{}, errors.New("enrollment not found")
	}

	if !now.Before(enrollment.Expires) {
		enrollment.State = "expired"
		return "", time.Time{}, errEnrollmentExpired
	}

	if enrollment.State != "verified" || enrollment.Device == nil || enrollment.PublicKey == nil || enrollment.MLDSA65PublicKey == nil {
		return "", time.Time{}, errors.New("enrollment is not ready")
	}

	p256Signature, err := b64.DecodeString(signatures["p256"])
	if err != nil || !ecdsa.VerifyASN1(enrollment.PublicKey, sum([]byte(enrollment.Payload)), p256Signature) {
		return "", time.Time{}, errors.New("invalid enrollment signature")
	}

	mldsaSignature, err := b64.DecodeString(signatures["mldsa65"])
	if err != nil || len(mldsaSignature) != mldsa.MLDSA65().SignatureSize() || mldsa.Verify(enrollment.MLDSA65PublicKey, []byte(enrollment.Payload), mldsaSignature, &mldsa.Options{}) != nil {
		return "", time.Time{}, errors.New("invalid enrollment signature")
	}

	issuedAt := now
	expiresAt := issuedAt.Add(cfg.Lifetimes.Credential)
	credential, err := s.signCredentialAt(enrollment.Device, cfg, issuedAt)
	if err != nil {
		return "", time.Time{}, err
	}

	enrollment.State = "complete"
	return credential, expiresAt, nil
}

func (s *Store) finishApproved(id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	login := s.loginState[id]
	if login == nil {
		return "", errors.New("login not found")
	}

	if login.State != "approved" || login.Device == nil {
		return "", errors.New("not approved")
	}

	if expireLoginIfNeeded(login, time.Now()) {
		return "", errors.New("login expired")
	}

	value, err := randomToken(24)
	if err != nil {
		return "", err
	}

	sub := hash("relay/subject\n" + login.Device.UpstreamNamespace + "\n" + login.Device.UpstreamSub)
	s.authCodes[value] = &AuthCode{
		Value:         value,
		ClientID:      login.ClientID,
		RedirectURI:   login.RedirectURI,
		CodeChallenge: login.PKCE,
		Sub:           sub,
		Email:         login.Device.Email,
		IdentityName:  login.Device.IdentityName,
		Nonce:         login.Nonce,
		Scope:         login.Scope,
		Expires:       time.Now().Add(oidcAuthorizationCodeLifetime),
	}

	login.State = "completed"

	return value, nil
}

func (s *Store) expireEnrollment(id string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.expireEnrollmentIfNeeded(s.enrollmentState[id], now)
}

func (s *Store) transitionLogin(id, expected, next string, device *Device) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	login := s.loginState[id]
	if login == nil {
		return "", errors.New("login not found")
	}

	if login.State != expected {
		return "", errors.New("invalid login transition")
	}

	if expireLoginIfNeeded(login, time.Now()) {
		return "", errors.New("login expired")
	}

	if !validLoginTransition(expected, next) {
		return "", errors.New("invalid login transition")
	}

	login.State = next
	if device != nil {
		login.Device = device
	}

	return login.State, nil
}

func validLoginTransition(from, to string) bool {
	return from == "pending" && (to == "approved" || to == "denied" || to == "expired") || from == "approved" && (to == "completed" || to == "expired")
}

func expireLoginIfNeeded(login *Login, now time.Time) bool {
	if login == nil || now.Before(login.Expires) {
		return false
	}

	if login.State == "pending" || login.State == "approved" {
		login.State = "expired"
		return true
	}

	return false
}

func (s *Store) expireLogin(id string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return expireLoginIfNeeded(s.loginState[id], now)
}

type Store struct {
	mu                    sync.RWMutex
	upstreamProviderMu    sync.Mutex
	startedAt             time.Time
	loginState            map[string]*Login
	enrollmentState       map[string]*Enrollment
	authCodes             map[string]*AuthCode
	mobileCodes           map[string]*MobileCode
	watchCapabilities     map[string]*WatchCapability
	upstreamStates        map[string]*UpstreamState
	replayNonces          map[string]time.Time
	rateBook              *rateBook
	systemStatsMu         sync.Mutex
	systemStatsAt         time.Time
	systemStats           *systemStatus
	deviceCredentialKey   []byte
	oidc                  *ecdsa.PrivateKey
	upstreamProviderSlots map[string]*upstreamProviderSlot
}

func (s *Store) currentSystemStatus() *systemStatus {
	s.systemStatsMu.Lock()
	defer s.systemStatsMu.Unlock()

	now := time.Now()
	if s.systemStats != nil && now.Sub(s.systemStatsAt) < 2*time.Second {
		return s.systemStats
	}

	value := readSystemStatus()
	if value == nil {
		return nil
	}

	s.systemStats = value
	s.systemStatsAt = now
	return value
}

type upstreamProviderSlot struct {
	mu       sync.Mutex
	provider *oauth.Provider
}

type statusStats struct {
	logins, enrollments, authorizationCodes, mobileCodes, upstreamTransactions int
}

func (s *Store) statusStats() statusStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return statusStats{
		logins:               len(s.loginState),
		enrollments:          len(s.enrollmentState),
		authorizationCodes:   len(s.authCodes),
		mobileCodes:          len(s.mobileCodes),
		upstreamTransactions: len(s.upstreamStates),
	}
}

func newStore(cfg Config) (*Store, error) {
	o, err := configuredSigningKey(cfg.OIDCSigningKeyB64, cfg.OIDCSigningKeyFile, cfg.Development)
	if err != nil {
		return nil, err
	}

	deviceCredentialKey, err := configuredCredentialKey(cfg.DeviceCredentialKeyB64, cfg.Development)
	if err != nil {
		return nil, err
	}

	store := &Store{
		startedAt:             time.Now(),
		loginState:            map[string]*Login{},
		enrollmentState:       map[string]*Enrollment{},
		authCodes:             map[string]*AuthCode{},
		mobileCodes:           map[string]*MobileCode{},
		watchCapabilities:     map[string]*WatchCapability{},
		upstreamStates:        map[string]*UpstreamState{},
		replayNonces:          map[string]time.Time{},
		rateBook:              newRateBook(),
		deviceCredentialKey:   deviceCredentialKey,
		oidc:                  o,
		upstreamProviderSlots: map[string]*upstreamProviderSlot{},
	}

	providers, err := configureOAuth(cfg)
	if err != nil {
		return nil, err
	}

	for id, provider := range providers {
		store.upstreamProviderSlots[id] = &upstreamProviderSlot{provider: provider}
	}

	return store, nil
}

func (s *Store) cleanupExpired() {
	now := time.Now()
	s.mu.Lock()
	for id, login := range s.loginState {
		if now.After(login.Expires) {
			delete(s.loginState, id)
		}
	}

	for id, enrollment := range s.enrollmentState {
		if now.After(enrollment.Expires) {
			delete(s.enrollmentState, id)
		}
	}

	for code, authCode := range s.authCodes {
		if now.After(authCode.Expires) {
			delete(s.authCodes, code)
		}
	}

	for code, mobile := range s.mobileCodes {
		if now.After(mobile.ExpiresAt) {
			delete(s.mobileCodes, code)
		}
	}

	for token, capability := range s.watchCapabilities {
		if now.After(capability.ExpiresAt) {
			delete(s.watchCapabilities, token)
		}
	}

	for value, state := range s.upstreamStates {
		if now.After(state.ExpiresAt) {
			delete(s.upstreamStates, value)
		}
	}

	for nonce, expires := range s.replayNonces {
		if now.After(expires) {
			delete(s.replayNonces, nonce)
		}
	}

	s.mu.Unlock()
	s.rateBook.cleanup()
}
