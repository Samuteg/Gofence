package surface

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// ntlmAuthenticator executa o handshake NTLMv2 sobre HTTP e devolve o
// cabeçalho Authorization final (type3) para reuso nas requisições.
type ntlmAuthenticator struct {
	client    *http.Client
	user, domain, pass string
}

func newNTLM(userPass string) *ntlmAuthenticator {
	user := userPass
	domain := ""
	if i := strings.Index(userPass, "\\"); i >= 0 {
		domain = userPass[:i]
		user = userPass[i+1:]
	} else if i := strings.Index(userPass, "/"); i >= 0 {
		domain = userPass[:i]
		user = userPass[i+1:]
	}
	pass := ""
	if i := strings.Index(user, ":"); i >= 0 {
		pass = user[i+1:]
		user = user[:i]
	}
	return &ntlmAuthenticator{client: http.DefaultClient, user: user, domain: domain, pass: pass}
}

// handshake roda type1 → (401) → type3 e retorna o token Authorization.
func (n *ntlmAuthenticator) handshake(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(ntlmType1()))

	resp, err := n.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		return "", fmt.Errorf("NTLM: expected 401 challenge, got %d", resp.StatusCode)
	}

	challenge := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(strings.ToLower(challenge), "ntlm ") {
		return "", fmt.Errorf("NTLM: no NTLM challenge in response")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(challenge[5:]))
	if err != nil {
		return "", fmt.Errorf("NTLM: bad challenge: %w", err)
	}
	type2, err := parseNTLMType2(raw)
	if err != nil {
		return "", err
	}

	type3 := ntlmType3(n.user, n.domain, n.pass, type2.challenge)
	return "NTLM " + base64.StdEncoding.EncodeToString(type3), nil
}

// ---- mensagens NTLM ----

// ntlmType1 monta a mensagem Type 1 (negociação), mínima.
func ntlmType1() []byte {
	msg := make([]byte, 32)
	copy(msg[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 1) // Type 1
	// Flags: NEGOTIATE_NTLM2 | NEGOTIATE_OEM | NEGOTIATE_UNICODE |
	// NEGOTIATE_SIGN | NEGOTIATE_SEAL | NEGOTIATE_ALWAYS_SIGN
	binary.LittleEndian.PutUint32(msg[12:16], 0x00088207)
	return msg
}

type ntlmType2Info struct {
	challenge [8]byte
}

// parseNTLMType2 extrai o challenge do servidor da mensagem Type 2.
func parseNTLMType2(msg []byte) (*ntlmType2Info, error) {
	if len(msg) < 32 || string(msg[0:8]) != "NTLMSSP\x00" {
		return nil, fmt.Errorf("NTLM: bad type2 signature")
	}
	if binary.LittleEndian.Uint32(msg[8:12]) != 2 {
		return nil, fmt.Errorf("NTLM: not a type2 message")
	}
	var info ntlmType2Info
	copy(info.challenge[:], msg[24:32])
	return &info, nil
}

// ntlmType3 monta a resposta Type 3 com NTLMv2 (LMv2+NTv2).
func ntlmType3(user, domain, pass string, serverChallenge [8]byte) []byte {
	userU := utf16.Encode([]rune(user))
	domainU := utf16.Encode([]rune(domain))
	passU := utf16.Encode([]rune(pass))

	// NTLMv2 hash (NTOWFv2).
	md4 := md4Hash(bytesFromUint16(passU))
	userDomain := append(bytesFromUint16(userU), bytesFromUint16(domainU)...)
	ntv2 := hmacMD5(md4, userDomain)

	// Blob: timestamp + client challenge + zeros.
	clientChal := make([]byte, 8)
	rand.Read(clientChal)
	ts := uint64(time.Now().Unix()) + 11644473600 // janela→unix
	blob := make([]byte, 28)
	binary.LittleEndian.PutUint32(blob[0:4], 0x01010000) // RespType/Length
	binary.LittleEndian.PutUint64(blob[4:12], ts)
	copy(blob[12:20], clientChal)
	binary.LittleEndian.PutUint32(blob[20:24], 0) // ChannelBindings length

	// NTProofStr = HMAC_MD5(NTOWFv2, serverChallenge + blob)
	proofInput := append(serverChallenge[:], blob...)
	ntProof := hmacMD5(ntv2, proofInput)
	ntResponse := append(ntProof, blob...)

	// LMv2: HMAC_MD5(NTOWFv2, serverChallenge + clientChallenge) + clientChal
	lmInput := append(serverChallenge[:], clientChal...)
	lmProof := hmacMD5(ntv2, lmInput)
	lmResponse := append(lmProof, clientChal...)

	// Type3 com os campos mínimos.
	lmLen := len(lmResponse)
	ntLen := len(ntResponse)
	secBufLen := lmLen + ntLen

	msg := make([]byte, 64+secBufLen)
	copy(msg[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 3) // Type 3
	// LM response security buffer @56
	msg[12] = byte(lmLen)
	msg[13] = byte(lmLen >> 8)
	msg[14], msg[15] = byte(64), 0
	// NT response security buffer @68
	msg[20] = byte(ntLen)
	msg[21] = byte(ntLen >> 8)
	msg[22], msg[23] = byte(64+lmLen), 0
	// Flags
	binary.LittleEndian.PutUint32(msg[60:64], 0x00088207)

	copy(msg[64:64+lmLen], lmResponse)
	copy(msg[64+lmLen:], ntResponse)
	return msg
}

func bytesFromUint16(in []uint16) []byte {
	out := make([]byte, len(in)*2)
	for i, v := range in {
		binary.LittleEndian.PutUint16(out[i*2:], v)
	}
	return out
}

func hmacMD5(key, data []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func md4Hash(data []byte) []byte {
	// MD4 não está na stdlib; golang.org/x/crypto/md4 é o padrão p/ NTLM.
	h := md4.New()
	h.Write(data)
	return h.Sum(nil)
}