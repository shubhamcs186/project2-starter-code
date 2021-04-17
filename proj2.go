package proj2

// CS 161 Project 2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	"github.com/cs161-staff/userlib"

	// The JSON library will be useful for serializing go structs.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/json.html.
	"encoding/json"

	// Likewise, useful for debugging, etc.
	"encoding/hex"

	// The Datastore requires UUIDs to store key-value entries.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/uuid.html.
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// User is the structure definition for a user record.
type User struct {
	Username string
	PkeSecretKey userlib.PKEDecKey
	DsSecretKey userlib.DSSignKey
	HmacKey []byte
	SymmEncKey []byte
	FileNameToMetaData map[string]HeaderLocation
	OwnedFilesToInvitations map[string][]InvitationInformation
	ReceivedFilesToInvitations map[string]ReceivedFileInformation
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type HeaderLocation struct {
	HeaderUuid uuid.UUID
	HeaderPrimaryKey []byte
}

type InvitationInformation struct {
	SentToken uuid.UUID
	InvitationEncryptionKey []byte
	Recipient string
}

type ReceivedFileInformation struct {
	RecievedToken uuid.UUID
	InvitationEncryptionKey []byte
	Owner string
}


// InitUser will be called a single time to initialize a new user.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	//TODO: This is a toy implementation.
	userdata.Username = username
	if username == "" || password == "" {
		return nil, errors.New(strings.ToTitle("Username and password can't be empty."))
	}
	_, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(username + "0"))))
	if ok {
		return nil, errors.New(strings.ToTitle("Username already exists."))
	}
	var RsaPublicKey userlib.PKEEncKey
	//var err1 error
	var DsVerKey userlib.DSVerifyKey
	var ByteUserStruct []byte
	var StructMac []byte
	var UserID uuid.UUID
	RsaPublicKey, userdata.PkeSecretKey, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	userdata.DsSecretKey, DsVerKey, err = userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	userlib.KeystoreSet(string(userlib.Hash([]byte(username + "0"))), RsaPublicKey)
	userlib.KeystoreSet(string(userlib.Hash([]byte(username + "1"))), DsVerKey)
	HmacAndEncKeys := userlib.Argon2Key(userlib.Hash([]byte(password)), []byte(username), 32)
	userdata.HmacKey = HmacAndEncKeys[:16]
	userdata.SymmEncKey = HmacAndEncKeys[16:]
	ByteUserStruct, err = json.Marshal(userdata)
	if err != nil {
		return nil, err
	}
	AmountToPad := 16 - (len(ByteUserStruct) % 16)
	for i := 0; i < AmountToPad; i++ {
		ByteUserStruct = append(ByteUserStruct, byte(AmountToPad))
	}
	StructEnc := userlib.SymEnc(userdata.SymmEncKey, userlib.RandomBytes(16), ByteUserStruct)
	StructMac, err = userlib.HMACEval(userdata.HmacKey, StructEnc)
	if err != nil {
		return nil, err
	}
	StructEnc = append(StructMac, StructEnc...)
	UserID, err = uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(UserID, StructEnc)
	//End of toy implementation
	return &userdata, err
}

// GetUser is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/getuser.html
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	_, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(username + "0"))))
	if !ok {
		return nil, errors.New(strings.ToTitle("Username doesn't exist."))
	}
	var UserID uuid.UUID
	var SupposedHmac []byte
	SupposedHmacAndEncKeys := userlib.Argon2Key(userlib.Hash([]byte(password)), []byte(username), 32) 
	SupposedHmacKey := SupposedHmacAndEncKeys[:16]
	SupposedEncKey := SupposedHmacAndEncKeys[16:]
	UserID, err = uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, err
	}
	ActualHmacAndStructEnc, _ := userlib.DatastoreGet(UserID)
	ActualHmac := ActualHmacAndStructEnc[:64]
	SupposedHmac, err = userlib.HMACEval(SupposedHmacKey, ActualHmacAndStructEnc[64:])
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(ActualHmac, SupposedHmac) {
		return nil, errors.New(strings.ToTitle("User can't be authenticated or integrity compromised."))
	}
	StructDecrypt := userlib.SymDec(SupposedEncKey, ActualHmacAndStructEnc[64:])
	LastByte := StructDecrypt[len(StructDecrypt) - 1]
	StructDecrypt = StructDecrypt[:(len(StructDecrypt) - int(LastByte))]
	err = json.Unmarshal(StructDecrypt, userdataptr)
	if err != nil {
		return nil, err
	}
	hmacEq := true
	for i := range userdataptr.HmacKey {
        if userdataptr.HmacKey[i] != SupposedHmacKey[i] {
            hmacEq = false
        }
    }
	symmEq := true
	for i := range userdataptr.SymmEncKey {
        if userdataptr.SymmEncKey[i] != SupposedEncKey[i] {
            symmEq = false
        }
    }
	if !hmacEq || !symmEq {
		return nil, errors.New(strings.ToTitle("User can't be authenticated."))
	}
	return userdataptr, nil
}

// StoreFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/storefile.html
func (userdata *User) StoreFile(filename string, data []byte) (err error) {

	//TODO: This is a toy implementation.
	storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	jsonData, _ := json.Marshal(data)
	userlib.DatastoreSet(storageKey, jsonData)
	//End of toy implementation

	return
}

// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	return
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {

	//TODO: This is a toy implementation.
	storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("File not found!"))
	}
	json.Unmarshal(dataJSON, &dataBytes)
	return dataBytes, nil
	//End of toy implementation

	return
}

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
func (userdata *User) ShareFile(filename string, recipient string) (
	accessToken uuid.UUID, err error) {

	return
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
func (userdata *User) ReceiveFile(filename string, sender string,
	accessToken uuid.UUID) error {
	return nil
}

// RevokeFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {
	return
}
