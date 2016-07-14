package toyls

type alertLevel byte
type alertDescription byte

const (
	warning alertLevel = 1
	fatal   alertLevel = 2
)

const (
	closeNotify               alertDescription = 0
	unexpectedMessage         alertDescription = 10
	badRecordMac              alertDescription = 20
	decryptionFailedReserved  alertDescription = 21
	recordOverflow            alertDescription = 22
	decompressionFailure      alertDescription = 30
	handshakeFailure          alertDescription = 40
	noCertificateReserved     alertDescription = 41
	badCertificate            alertDescription = 42
	unsupportedCertificate    alertDescription = 43
	certificateRevoked        alertDescription = 44
	certificateExpired        alertDescription = 45
	certificateUnknown        alertDescription = 46
	illegalParameter          alertDescription = 47
	unknownCA                 alertDescription = 48
	accessDenied              alertDescription = 49
	decodeError               alertDescription = 50
	decryptError              alertDescription = 51
	exportRestrictionReserved alertDescription = 60
	protocolVersionError      alertDescription = 70
	insufficientSecurity      alertDescription = 71
	internalError             alertDescription = 80
	userCanceled              alertDescription = 90
	noRenegotiation           alertDescription = 100
	unsupportedExtension      alertDescription = 110
)

type alertMessage struct {
	level       alertLevel
	description alertDescription
}

func (m *alertMessage) marshall() []byte {
	return []byte{byte(m.level), byte(m.description)}
}
