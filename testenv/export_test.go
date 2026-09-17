package testenv

// Internals the oracle tests need. Keeping them here rather than in the public
// API means the version-banner parsing can be tested against captured logs
// without committing it as a supported surface.

// OpenVPNBannerForTest exposes openvpnBanner to the external test package.
var OpenVPNBannerForTest = openvpnBanner

// ReleaseFromBannerForTest exposes releaseFromBanner to the external test
// package.
var ReleaseFromBannerForTest = releaseFromBanner

// AuthVerifyScriptForTest exposes authVerifyScript to the external test package,
// so the server-side hook can be checked against the same constants the
// client-side credentials file is built from. It is not a supported surface.
var AuthVerifyScriptForTest = authVerifyScript

// CredentialsFileBodyForTest exposes credentialsFileBody to the external test
// package, for the same reason.
var CredentialsFileBodyForTest = credentialsFileBody

// ClientCredentialsPathForTest is the in-container path ContainerProfile points
// auth-user-pass at, exposed so a test can assert the profile and the bundle
// agree on where the file lands.
const ClientCredentialsPathForTest = clientCredentialsPath

// ServerAuthVerifyPathForTest is the in-container path the server's
// auth-user-pass-verify directive names.
const ServerAuthVerifyPathForTest = serverAuthVerifyPath

// AuthVerifyFileNameForTest is the hook's base name in the bundle. The image
// entrypoint spells it out too, so a test has to be able to compare them.
const AuthVerifyFileNameForTest = authVerifyFileName

// NewMatrixPKIForTest exposes newMatrixPKI, so that the certificate an axis
// asks for can be inspected without a Docker daemon. StartMatrix is the
// supported way to obtain a MatrixPKI.
var NewMatrixPKIForTest = newMatrixPKI

// NSCertTypeOIDForTest is the Netscape certificate-type extension's object
// identifier, exposed so a test can find the extension in a generated
// certificate rather than re-spelling the OID.
var NSCertTypeOIDForTest = nsCertTypeOID

// ClientCAPathForTest is the in-container path a CAFile entry's
// ContainerProfile points its `ca` directive at.
const ClientCAPathForTest = clientCAPath
