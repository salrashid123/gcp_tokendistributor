package oid

// Trusted Computing Group (2.23.133)
var (
	TPMManufacturer            = []int{2, 23, 133, 2, 1}
	TPMModel                   = []int{2, 23, 133, 2, 2}
	TPMVersion                 = []int{2, 23, 133, 2, 3}
	TCGPlatformSpecification   = []int{2, 23, 133, 2, 17}
	TBBSecurityAssertions      = []int{2, 23, 133, 2, 19}
	TPMSpecification           = []int{2, 23, 133, 2, 16}
	TCGCredentialSpecification = []int{2, 23, 133, 2, 23}
	TCGCredentialType          = []int{2, 23, 133, 2, 25}
	PlatformManufacturerStr    = []int{2, 23, 133, 5, 1, 1}
	PlatformManufacturerID     = []int{2, 23, 133, 5, 1, 2}
	PlatformConfigURI          = []int{2, 23, 133, 5, 1, 3}
	PlatformModel              = []int{2, 23, 133, 5, 1, 4}
	PlatformVersion            = []int{2, 23, 133, 5, 1, 5}
	PlatformSerial             = []int{2, 23, 133, 5, 1, 6}
	PlatformConfigurationV1    = []int{2, 23, 133, 5, 1, 7, 1}
	PlatformConfigurationV2    = []int{2, 23, 133, 5, 1, 7, 2}
	EKCertificate              = []int{2, 23, 133, 8, 1}
	VerifiedTPMRestricted      = []int{2, 23, 133, 11, 1, 3}
	EKPermIDSHA256             = []int{2, 23, 133, 12, 1}
)

// X.509 (2.23.23)
//
// https://www.itu.int/ITU-T/recommendations/rec.aspx?rec=14033
// https://tools.ietf.org/html/rfc5280
var (
	SubjectDirectoryAttributes = []int{2, 5, 29, 9}
	SubjectAltName             = []int{2, 5, 29, 17}
	CertificatePolicies        = []int{2, 5, 29, 32}
)

// RFC 4043
//
// https://tools.ietf.org/html/rfc4043
var (
	PermanentIdentifier = []int{1, 3, 6, 1, 5, 5, 7, 8, 3}
)

// Google (1.3.6.1.4.1.11129)
var (
	CloudComputeInstanceIdentifier = []int{1, 3, 6, 1, 4, 1, 11129, 2, 1, 21}
)
