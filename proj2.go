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

type FileHeader struct {
	OwnerEncrypted []byte
	FileLength int
	PageUUIDS []uuid.UUID
	PagePrimaryKeys [][]byte
}

type FileDataPage struct {
	FileData string
}

type Invitation struct {
	FileHeaderUUID uuid.UUID
	FileHeaderPKey []byte
}


// InitUser will be called a single time to initialize a new user.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	//TODO: This is a toy implementation.
	userdata.Username = username
	//Error Checks
	if username == "" || password == "" {
		return nil, errors.New(strings.ToTitle("Username and password can't be empty."))
	}
	_, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(username + "0"))))
	if ok {
		return nil, errors.New(strings.ToTitle("Username already exists."))
	}

	//Generate and store user public keys
	var RsaPublicKey userlib.PKEEncKey
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

	//Generate user HMAC and Encrypt keys and marshal user struct
	HmacAndEncKeys := userlib.Argon2Key(userlib.Hash([]byte(password)), []byte(username), 32)
	userdata.HmacKey = HmacAndEncKeys[:16]
	userdata.SymmEncKey = HmacAndEncKeys[16:]
	tempA := make(map[string]HeaderLocation)
	userdata.FileNameToMetaData = tempA
	tempB := make(map[string][]InvitationInformation)
	userdata.OwnedFilesToInvitations = tempB
	tempC := make(map[string]ReceivedFileInformation)
	userdata.ReceivedFilesToInvitations = tempC
	ByteUserStruct, err = json.Marshal(userdata)
	if err != nil {
		return nil, err
	}

	//Pad, Encrypt, and HMAC
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

	//Generate UUID to store user and store
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

	//Error checks
	_, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(username + "0"))))
	if !ok {
		return nil, errors.New(strings.ToTitle("Username doesn't exist."))
	}

	//Generate HMAC, Encrypt, UUID from input username & pwd
	var UserID uuid.UUID
	var SupposedHmac []byte
	SupposedHmacAndEncKeys := userlib.Argon2Key(userlib.Hash([]byte(password)), []byte(username), 32) 
	SupposedHmacKey := SupposedHmacAndEncKeys[:16]
	SupposedEncKey := SupposedHmacAndEncKeys[16:]
	UserID, err = uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, err
	}

	//Pull actual HMAC and verify integrity/authenticate -> make sure to do length of HMAC check
	ActualHmacAndStructEnc, _ := userlib.DatastoreGet(UserID)
	if len(ActualHmacAndStructEnc) < 64 {
		return nil, errors.New(strings.ToTitle("Integrity compromised."))
	}
	ActualHmac := ActualHmacAndStructEnc[:64]
	SupposedHmac, err = userlib.HMACEval(SupposedHmacKey, ActualHmacAndStructEnc[64:])
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(ActualHmac, SupposedHmac) {
		return nil, errors.New(strings.ToTitle("User can't be authenticated or integrity compromised."))
	}

	//Decrypt, depad, and unmarshal User struct
	StructDecrypt := userlib.SymDec(SupposedEncKey, ActualHmacAndStructEnc[64:])
	LastByte := StructDecrypt[len(StructDecrypt) - 1]
	StructDecrypt = StructDecrypt[:(len(StructDecrypt) - int(LastByte))]
	err = json.Unmarshal(StructDecrypt, userdataptr)
	if err != nil {
		return nil, err
	}

	//Authenticate user by checking if generated keys same as actual keys
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
	// tempX := *(userdataptr.FileNameToMetaData)
	// tempX["blah"] = HeaderLocation{uuid.New(), []byte("blah")}
	//userlib.DebugMsg("%v", (len((*(userdataptr.FileNameToMetaData)))))
	//for key, value := range (*(userdataptr.FileNameToMetaData)) {
	//	userlib.DebugMsg("Key:", key, "Value:", value)
	//}
	return userdataptr, nil
}

// StoreFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/storefile.html
func (userdata *User) StoreFile(filename string, data []byte) (err error) {

	//TODO: This is a toy implementation.
	// storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	// jsonData, _ := json.Marshal(data)
	// userlib.DatastoreSet(storageKey, jsonData)
	//End of toy implementation

	var fileHeaderUUID userlib.UUID
	var fileHeaderPrimaryKey []byte
	var derivedFileHeaderKeys []byte
	var fileHeader FileHeader
	var fileHeaderptr = &fileHeader

	var firstUserID uuid.UUID
	firstUserID, err = uuid.FromBytes(userlib.Hash([]byte(userdata.Username))[:16])
	if err != nil {
		return err
	}

	//Pull actual HMAC and verify integrity/authenticate -> make sure to do length of HMAC check
	ActualHmacAndStructEnc, _ := userlib.DatastoreGet(firstUserID)
	if len(ActualHmacAndStructEnc) < 64 {
		return errors.New(strings.ToTitle("Integrity compromised."))
	}
	ActualHmac := ActualHmacAndStructEnc[:64]
	var SupposedHmac []byte
	SupposedHmac, err = userlib.HMACEval(userdata.HmacKey, ActualHmacAndStructEnc[64:])
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(ActualHmac, SupposedHmac) {
		return errors.New(strings.ToTitle("User can't be authenticated or integrity compromised."))
	}

	//Decrypt, depad, and unmarshal User struct
	StructDecrypt := userlib.SymDec(userdata.SymmEncKey, ActualHmacAndStructEnc[64:])
	LastByte := StructDecrypt[len(StructDecrypt) - 1]
	StructDecrypt = StructDecrypt[:(len(StructDecrypt) - int(LastByte))]
	err = json.Unmarshal(StructDecrypt, userdata)
	if err != nil {
		return err
	}

	// userlib.DebugMsg("%v", (len((*(userdataptr.FileNameToMetaData)))))
	// for key, value := range (*(userdataptr.FileNameToMetaData)) {
	// 	userlib.DebugMsg("Key:", key, "Value:", value)
	// }

	//Get File header UUID and PrimaryKey from user's 1st hashmap (if exists)
	tempA := userdata.FileNameToMetaData
	fileHeaderData, ok := tempA[filename]
	
	//File exists
	if ok {
		tempB := userdata.OwnedFilesToInvitations
		fileInvitationInfo, okk := tempB[filename]
		_ = fileInvitationInfo
		//User is owner
		if okk {
			fileHeaderUUID = fileHeaderData.HeaderUuid
			fileHeaderPrimaryKey = fileHeaderData.HeaderPrimaryKey
		//User is shared
		} else {
			
			//Get invitation via location and verify authenticity with Owner DS Public Key.
			tempC := userdata.ReceivedFilesToInvitations
			receivedFileInfo, okkk := tempC[filename]
			_ = okkk
			fileInvitation, okkkk := userlib.DatastoreGet(receivedFileInfo.RecievedToken)
			_ = okkkk
			tempD := userdata.ReceivedFilesToInvitations
			OwnerKey, ook := userlib.KeystoreGet(string(userlib.Hash([]byte(tempD[filename].Owner + "1"))))
			_ = ook

			//length Check
			if len(fileInvitation) < 256 {
				return errors.New(strings.ToTitle("Integrity compromised."))
			}

			err = userlib.DSVerify(OwnerKey, fileInvitation[256:], fileInvitation[:256])
			if err != nil {
				return err
			}
			
			//Decrypt (using invitation key (only 1)), depad, and unmarshal invitation.
			InvitationStructDecrypt := userlib.SymDec(receivedFileInfo.InvitationEncryptionKey, fileInvitation[256:])
			LastByte := InvitationStructDecrypt[len(InvitationStructDecrypt) - 1]
			InvitationStructDecrypt = InvitationStructDecrypt[:(len(InvitationStructDecrypt) - int(LastByte))]
			var invitationData Invitation
			var invitationdataptr = &invitationData
			err = json.Unmarshal(InvitationStructDecrypt, invitationdataptr)
			if err != nil {
				return err
			}
			
			//Update hashmap of file header UUID + PrimaryKey with invitation info as necessary. (if recent revoking)
			if invitationdataptr.FileHeaderUUID != fileHeaderData.HeaderUuid {
				fileHeaderData.HeaderUuid = invitationData.FileHeaderUUID
			}
			for i := range invitationdataptr.FileHeaderPKey {
        		if invitationdataptr.FileHeaderPKey[i] != fileHeaderData.HeaderPrimaryKey[i] {
            		fileHeaderData.HeaderPrimaryKey[i] = invitationdataptr.FileHeaderPKey[i]
        		}
    		}
			fileHeaderUUID = fileHeaderData.HeaderUuid
			fileHeaderPrimaryKey = fileHeaderData.HeaderPrimaryKey
		}
		
		//Both owner and shared
		//Access Fileheader and check for integrity by deriving file header HMAC and Encrypt keys from PrimaryKey. -> length check too
		fileHeaderStructAndMac, ookk := userlib.DatastoreGet(fileHeaderUUID)
		_ = ookk
		derivedFileHeaderKeys, err = userlib.HashKDF(fileHeaderPrimaryKey, []byte("derivedfileheaderkeys"))

		if len(fileHeaderStructAndMac) < 64 {
			return errors.New(strings.ToTitle("Integrity compromised."))
		}

		ActualHeaderMac := fileHeaderStructAndMac[:64]
		var SupposedHmac []byte
		SupposedHmac, err = userlib.HMACEval(derivedFileHeaderKeys[16:32], fileHeaderStructAndMac[64:])
		if err != nil {
			return err
		}
		if !userlib.HMACEqual(ActualHeaderMac, SupposedHmac) {
			return errors.New(strings.ToTitle("User can't be authenticated or integrity compromised."))
		}
		
		//Decrypt, depad, and unmarshal fileheader.
		FileHeaderStructDecrypt := userlib.SymDec(derivedFileHeaderKeys[:16], fileHeaderStructAndMac[64:])
		LastByte := FileHeaderStructDecrypt[len(FileHeaderStructDecrypt) - 1]
		FileHeaderStructDecrypt = FileHeaderStructDecrypt[:(len(FileHeaderStructDecrypt) - int(LastByte))]
		err = json.Unmarshal(FileHeaderStructDecrypt, fileHeaderptr)
		if err != nil {
			return err
		}
		
		//Clear all existing pages.
		for i := 0; i < fileHeaderptr.FileLength; i++ {
			userlib.DatastoreSet(fileHeaderptr.PageUUIDS[i], []byte(""))
			//Erase PagePrimaryKeys
			fileHeaderptr.PagePrimaryKeys[i] = []byte("")
		}
	//File doesn't exit (new file created)
	} else {
		//userlib.DebugMsg("File Name: %v", filename)
		//userlib.DebugMsg("File Content: %v", string(data))
		// Make new file header (uuid, primary key)
		// Add new fileheader info struct to owner's first hashmap and initialize 2nd hashmap (owned files to array of structs) with empty list
		// initialize fileheader's owner field w/ owner name encrypted w/ owner's PKE public key
		// instantiate fileheader's pageUUIDs array field, and pagePrimaryKeys array field
		newFileHeaderUUID := uuid.New()
		newFileHeaderPrimaryKey := userlib.RandomBytes(16)
		newHeaderLocation := HeaderLocation{newFileHeaderUUID, newFileHeaderPrimaryKey}
		tempE := userdata.FileNameToMetaData
		tempE[filename] = newHeaderLocation
		tempF := userdata.OwnedFilesToInvitations
		tempF[filename] = make([]InvitationInformation, 1)
		userPKEKey, oook := userlib.KeystoreGet(string(userlib.Hash([]byte(userdata.Username + "0"))))
		_ = oook
		fileHeaderptr.OwnerEncrypted, err = userlib.PKEEnc(userPKEKey, []byte(userdata.Username))
		fileHeaderptr.PageUUIDS = make([]uuid.UUID, 1)
		fileHeaderptr.PagePrimaryKeys = make([][]byte, 1)
		if err != nil {
			return err
		}
	}
	
	//Both new and existing files
	//Generate new data page uuid & primary key and update file header fields (file length, PageUUIDS, PagePrimaryKeys).
	//Hash page's primarykey to derive page MAC and Encrypt keys
	newPageUUID := uuid.New()
	newPagePrimaryKey := userlib.RandomBytes(16)
	fileHeaderptr.FileLength = 1
	fileHeaderptr.PageUUIDS[0] = newPageUUID
	fileHeaderptr.PagePrimaryKeys[0] = newPagePrimaryKey
	var derivedPageKeys []byte
	derivedPageKeys, err = userlib.HashKDF(newPagePrimaryKey, []byte("derivedpagekeys"))
	if err != nil {
		return err
	}
	
	//Create and marshal data page struct
	newPageStruct := FileDataPage{string(data)}
	var BytesOfNewPageStruct []byte
	BytesOfNewPageStruct, err = json.Marshal(newPageStruct)
	if err != nil {
		return err
	}
	
	//Pad, Encrypt, HMAC, and store data page struct using previously derived keys.
	AmountToPad := 16 - (len(BytesOfNewPageStruct) % 16)
	for i := 0; i < AmountToPad; i++ {
		BytesOfNewPageStruct = append(BytesOfNewPageStruct, byte(AmountToPad))
	}
	encryptedPage := userlib.SymEnc(derivedPageKeys[:16], userlib.RandomBytes(16), BytesOfNewPageStruct)
	var newPageMac []byte
	newPageMac, err = userlib.HMACEval(derivedPageKeys[16:32], encryptedPage)
	if err != nil {
		return err
	}
	encryptedAndMacPage := append(newPageMac, encryptedPage...)
	userlib.DatastoreSet(newPageUUID, encryptedAndMacPage)
	
	//Marshal, Pad, Encrypt, HMAC, and store file header. Derive fileheaderkeys from user's 1st hashmap containing primaryKey
	var BytesOfFileHeaderStruct []byte
	BytesOfFileHeaderStruct, err = json.Marshal(*fileHeaderptr)
	if err != nil {
		return err
	}
	tempG := userdata.FileNameToMetaData
	derivedFileHeaderKeys, err = userlib.HashKDF(tempG[filename].HeaderPrimaryKey, []byte("derivedfileheaderkeys"))
	if err != nil {
		return err
	}
	AmountToPad = 16 - (len(BytesOfFileHeaderStruct) % 16)
	for i := 0; i < AmountToPad; i++ {
		BytesOfFileHeaderStruct = append(BytesOfFileHeaderStruct, byte(AmountToPad))
	}
	encryptedFileHeader := userlib.SymEnc(derivedFileHeaderKeys[:16], userlib.RandomBytes(16), BytesOfFileHeaderStruct)
	var fileHeaderMac []byte
	fileHeaderMac, err = userlib.HMACEval(derivedFileHeaderKeys[16:32], encryptedFileHeader)
	if err != nil {
		return err
	}
	encryptedAndMacFileHeader := append(fileHeaderMac, encryptedFileHeader...)
	tempH := userdata.FileNameToMetaData
	userlib.DatastoreSet(tempH[filename].HeaderUuid, encryptedAndMacFileHeader)

	//Marshal user struct
	var ByteUserStruct []byte
	ByteUserStruct, err = json.Marshal(userdata)
	if err != nil {
		return err
	}

	//Pad, Encrypt, and HMAC User Struct
	AmountToPad = 16 - (len(ByteUserStruct) % 16)
	for i := 0; i < AmountToPad; i++ {
		ByteUserStruct = append(ByteUserStruct, byte(AmountToPad))
	}
	StructEnc := userlib.SymEnc(userdata.SymmEncKey, userlib.RandomBytes(16), ByteUserStruct)
	var StructMac []byte
	StructMac, err = userlib.HMACEval(userdata.HmacKey, StructEnc)
	if err != nil {
		return err
	}
	StructEnc = append(StructMac, StructEnc...)

	//Generate UUID to store user and store
	var lastUserID uuid.UUID
	lastUserID, err = uuid.FromBytes(userlib.Hash([]byte(userdata.Username))[:16])
	if err != nil {
		return err
	}
	//userlib.DebugMsg("Initial: %v", firstUserID.String())
	//userlib.DebugMsg("Last: %v", lastUserID.String())
	userlib.DatastoreSet(lastUserID, StructEnc)
	return
}

// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	var fileHeaderUUID userlib.UUID
	var fileHeaderPrimaryKey []byte
	var derivedFileHeaderKeys []byte
	var fileHeader FileHeader
	var fileHeaderptr = &fileHeader

	//Error check: Get File header UUID and PrimaryKey from user's 1st hashmap (if exists)
	tempA := userdata.FileNameToMetaData
	fileHeaderData, ok := tempA[filename]
	if !ok {
		return errors.New(strings.ToTitle("User doesn't own file"))
	}
	tempB := userdata.OwnedFilesToInvitations
	fileInvitationInfo, okk := tempB[filename]
	_ = fileInvitationInfo
	//User is owner
	if okk {
		fileHeaderUUID = fileHeaderData.HeaderUuid
		fileHeaderPrimaryKey = fileHeaderData.HeaderPrimaryKey
	//User is shared
	} else {
		//Get invitation via location and verify authenticity with Owner DS Public Key.
		tempC := userdata.ReceivedFilesToInvitations
		receivedFileInfo, okkk := tempC[filename]
		_ = okkk
		fileInvitation, okkkk := userlib.DatastoreGet(receivedFileInfo.RecievedToken)
		_ = okkkk
		tempD := userdata.ReceivedFilesToInvitations
		OwnerKey, ook := userlib.KeystoreGet(string(userlib.Hash([]byte(tempD[filename].Owner + "1"))))
		_ = ook

		//length Check
		if len(fileInvitation) < 256 {
			return errors.New(strings.ToTitle("Integrity compromised."))
		}

		err = userlib.DSVerify(OwnerKey, fileInvitation[256:], fileInvitation[:256])
		if err != nil {
			return err
		}
		
		//Decrypt (using invitation key (only 1)), depad, and unmarshal invitation.
		InvitationStructDecrypt := userlib.SymDec(receivedFileInfo.InvitationEncryptionKey, fileInvitation[256:])
		LastByte := InvitationStructDecrypt[len(InvitationStructDecrypt) - 1]
		InvitationStructDecrypt = InvitationStructDecrypt[:(len(InvitationStructDecrypt) - int(LastByte))]
		var invitationData Invitation
		var invitationdataptr = &invitationData
		err = json.Unmarshal(InvitationStructDecrypt, invitationdataptr)
		if err != nil {
			return err
		}
		
		//Update hashmap of file header UUID + PrimaryKey with invitation info as necessary. (if recent revoking)
		if invitationdataptr.FileHeaderUUID != fileHeaderData.HeaderUuid {
			fileHeaderData.HeaderUuid = invitationData.FileHeaderUUID
		}
		for i := range invitationdataptr.FileHeaderPKey {
			if invitationdataptr.FileHeaderPKey[i] != fileHeaderData.HeaderPrimaryKey[i] {
				fileHeaderData.HeaderPrimaryKey[i] = invitationdataptr.FileHeaderPKey[i]
			}
		}
		fileHeaderUUID = fileHeaderData.HeaderUuid
		fileHeaderPrimaryKey = fileHeaderData.HeaderPrimaryKey
	}

	//Both owner and shared
	//Access Fileheader and check for integrity by deriving file header HMAC and Encrypt keys from PrimaryKey. -> length check too
	fileHeaderStructAndMac, ookk := userlib.DatastoreGet(fileHeaderUUID)
	_ = ookk
	derivedFileHeaderKeys, err = userlib.HashKDF(fileHeaderPrimaryKey, []byte("derivedfileheaderkeys"))

	if len(fileHeaderStructAndMac) < 64 {
		return errors.New(strings.ToTitle("Integrity compromised."))
	}

	ActualHeaderMac := fileHeaderStructAndMac[:64]
	var SupposedHmac []byte
	SupposedHmac, err = userlib.HMACEval(derivedFileHeaderKeys[16:32], fileHeaderStructAndMac[64:])
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(ActualHeaderMac, SupposedHmac) {
		return errors.New(strings.ToTitle("User can't be authenticated or integrity compromised."))
	}
	
	//Decrypt, depad, and unmarshal fileheader.
	FileHeaderStructDecrypt := userlib.SymDec(derivedFileHeaderKeys[:16], fileHeaderStructAndMac[64:])
	LastByte := FileHeaderStructDecrypt[len(FileHeaderStructDecrypt) - 1]
	FileHeaderStructDecrypt = FileHeaderStructDecrypt[:(len(FileHeaderStructDecrypt) - int(LastByte))]
	err = json.Unmarshal(FileHeaderStructDecrypt, fileHeaderptr)
	if err != nil {
		return err
	}

	//Generate new data page uuid & primary key and update file header fields (file length, PageUUIDS, PagePrimaryKeys).
	//Hash page's primarykey to derive page MAC and Encrypt keys
	newPageUUID := uuid.New()
	newPagePrimaryKey := userlib.RandomBytes(16)
	if fileHeaderptr.FileLength == len(fileHeaderptr.PageUUIDS) {
		fileHeaderptr.PageUUIDS = append(fileHeaderptr.PageUUIDS, newPageUUID)
		fileHeaderptr.PagePrimaryKeys = append(fileHeaderptr.PagePrimaryKeys, newPagePrimaryKey)
	} else {
		fileHeaderptr.PageUUIDS[fileHeaderptr.FileLength] = newPageUUID
		fileHeaderptr.PagePrimaryKeys[fileHeaderptr.FileLength] = newPagePrimaryKey
	}
	fileHeaderptr.FileLength = fileHeaderptr.FileLength + 1
	var derivedPageKeys []byte
	derivedPageKeys, err = userlib.HashKDF(newPagePrimaryKey, []byte("derivedpagekeys"))
	if err != nil {
		return err
	}

	//Create and marshal data page struct
	newPageStruct := FileDataPage{string(data)}
	var BytesOfNewPageStruct []byte
	BytesOfNewPageStruct, err = json.Marshal(newPageStruct)
	if err != nil {
		return err
	}

	//Pad, Encrypt, HMAC, and store data page struct using previously derived keys.
	AmountToPad := 16 - (len(BytesOfNewPageStruct) % 16)
	for i := 0; i < AmountToPad; i++ {
		BytesOfNewPageStruct = append(BytesOfNewPageStruct, byte(AmountToPad))
	}
	encryptedPage := userlib.SymEnc(derivedPageKeys[:16], userlib.RandomBytes(16), BytesOfNewPageStruct)
	var newPageMac []byte
	newPageMac, err = userlib.HMACEval(derivedPageKeys[16:32], encryptedPage)
	if err != nil {
		return err
	}
	encryptedAndMacPage := append(newPageMac, encryptedPage...)
	userlib.DatastoreSet(newPageUUID, encryptedAndMacPage)
	
	//Marshal, Pad, Encrypt, HMAC, and store file header. Derive fileheaderkeys from user's 1st hashmap containing primaryKey
	var BytesOfFileHeaderStruct []byte
	BytesOfFileHeaderStruct, err = json.Marshal(*fileHeaderptr)
	if err != nil {
		return err
	}
	tempE := userdata.FileNameToMetaData
	derivedFileHeaderKeys, err = userlib.HashKDF(tempE[filename].HeaderPrimaryKey, []byte("derivedfileheaderkeys"))
	if err != nil {
		return err
	}
	AmountToPad = 16 - (len(BytesOfFileHeaderStruct) % 16)
	for i := 0; i < AmountToPad; i++ {
		BytesOfFileHeaderStruct = append(BytesOfFileHeaderStruct, byte(AmountToPad))
	}
	encryptedFileHeader := userlib.SymEnc(derivedFileHeaderKeys[:16], userlib.RandomBytes(16), BytesOfFileHeaderStruct)
	var fileHeaderMac []byte
	fileHeaderMac, err = userlib.HMACEval(derivedFileHeaderKeys[16:32], encryptedFileHeader)
	if err != nil {
		return err
	}
	encryptedAndMacFileHeader := append(fileHeaderMac, encryptedFileHeader...)
	tempF := userdata.FileNameToMetaData
	userlib.DatastoreSet(tempF[filename].HeaderUuid, encryptedAndMacFileHeader)

	return
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {

	//TODO: This is a toy implementation.
	// storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	// dataJSON, ok := userlib.DatastoreGet(storageKey)
	// if !ok {
	// 	return nil, errors.New(strings.ToTitle("File not found!"))
	// }
	// json.Unmarshal(dataJSON, &dataBytes)
	// return dataBytes, nil
	//End of toy implementation

	var fileHeaderUUID userlib.UUID
	var fileHeaderPrimaryKey []byte
	var derivedFileHeaderKeys []byte
	var fileHeader FileHeader
	var fileHeaderptr = &fileHeader
	
	var UserID uuid.UUID
	UserID, err = uuid.FromBytes(userlib.Hash([]byte(userdata.Username))[:16])
	if err != nil {
		return nil, err
	}

	//Pull actual HMAC and verify integrity/authenticate -> make sure to do length of HMAC check
	ActualHmacAndStructEnc, _ := userlib.DatastoreGet(UserID)
	if len(ActualHmacAndStructEnc) < 64 {
		return nil, errors.New(strings.ToTitle("Integrity compromised."))
	}
	ActualHmac := ActualHmacAndStructEnc[:64]
	var SupposedHmac []byte
	SupposedHmac, err = userlib.HMACEval(userdata.HmacKey, ActualHmacAndStructEnc[64:])
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(ActualHmac, SupposedHmac) {
		return nil, errors.New(strings.ToTitle("User can't be authenticated or integrity compromised."))
	}

	//Decrypt, depad, and unmarshal User struct
	StructDecrypt := userlib.SymDec(userdata.SymmEncKey, ActualHmacAndStructEnc[64:])
	LastByte := StructDecrypt[len(StructDecrypt) - 1]
	StructDecrypt = StructDecrypt[:(len(StructDecrypt) - int(LastByte))]
	err = json.Unmarshal(StructDecrypt, userdata)
	if err != nil {
		return nil, err
	}
	
	//Error check: Get File header UUID and PrimaryKey from user's 1st hashmap (if exists)
	tempA := userdata.FileNameToMetaData
	fileHeaderData, ok := tempA[filename]
	if !ok {
		return nil, errors.New(strings.ToTitle("User doesn't have file"))
	}

	tempB := userdata.OwnedFilesToInvitations
	fileInvitationInfo, okk := tempB[filename]
	_ = fileInvitationInfo
	//User is owner
	if okk {
		fileHeaderUUID = fileHeaderData.HeaderUuid
		fileHeaderPrimaryKey = fileHeaderData.HeaderPrimaryKey
	//User is shared
	} else {
		//Get invitation via location and verify authenticity with Owner DS Public Key.
		tempC := userdata.ReceivedFilesToInvitations
		receivedFileInfo, okkk := tempC[filename]
		_ = okkk
		fileInvitation, okkkk := userlib.DatastoreGet(receivedFileInfo.RecievedToken)
		_ = okkkk
		tempD := userdata.ReceivedFilesToInvitations
		OwnerKey, ook := userlib.KeystoreGet(string(userlib.Hash([]byte(tempD[filename].Owner + "1"))))
		_ = ook

		//length Check
		if len(fileInvitation) < 256 {
			return nil, errors.New(strings.ToTitle("Integrity compromised."))
		}

		err = userlib.DSVerify(OwnerKey, fileInvitation[256:], fileInvitation[:256])
		if err != nil {
			return nil, err
		}

		//Decrypt (using invitation key (only 1)), depad, and unmarshal invitation.
		InvitationStructDecrypt := userlib.SymDec(receivedFileInfo.InvitationEncryptionKey, fileInvitation[256:])
		LastByte := InvitationStructDecrypt[len(InvitationStructDecrypt) - 1]
		InvitationStructDecrypt = InvitationStructDecrypt[:(len(InvitationStructDecrypt) - int(LastByte))]
		var invitationData Invitation
		var invitationdataptr = &invitationData
		err = json.Unmarshal(InvitationStructDecrypt, invitationdataptr)
		if err != nil {
			return nil, err
		}
		
		//Update hashmap of file header UUID + PrimaryKey with invitation info as necessary. (if recent revoking)
		if invitationdataptr.FileHeaderUUID != fileHeaderData.HeaderUuid {
			fileHeaderData.HeaderUuid = invitationData.FileHeaderUUID
		}
		for i := range invitationdataptr.FileHeaderPKey {
			if invitationdataptr.FileHeaderPKey[i] != fileHeaderData.HeaderPrimaryKey[i] {
				fileHeaderData.HeaderPrimaryKey[i] = invitationdataptr.FileHeaderPKey[i]
			}
		}
		fileHeaderUUID = fileHeaderData.HeaderUuid
		fileHeaderPrimaryKey = fileHeaderData.HeaderPrimaryKey
	}
	//Both owner and shared
	//Access Fileheader and check for integrity by deriving file header HMAC and Encrypt keys from PrimaryKey. -> length check too
	fileHeaderStructAndMac, ookk := userlib.DatastoreGet(fileHeaderUUID)
	_ = ookk
	derivedFileHeaderKeys, err = userlib.HashKDF(fileHeaderPrimaryKey, []byte("derivedfileheaderkeys"))

	if len(fileHeaderStructAndMac) < 64 {
		return nil, errors.New(strings.ToTitle("Integrity compromised."))
	}

	ActualHeaderMac := fileHeaderStructAndMac[:64]
	SupposedHmac, err = userlib.HMACEval(derivedFileHeaderKeys[16:32], fileHeaderStructAndMac[64:])
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(ActualHeaderMac, SupposedHmac) {
		return nil, errors.New(strings.ToTitle("User can't be authenticated or integrity compromised."))
	}

	//Decrypt, depad, and unmarshal fileheader.
	FileHeaderStructDecrypt := userlib.SymDec(derivedFileHeaderKeys[:16], fileHeaderStructAndMac[64:])
	LastByte = FileHeaderStructDecrypt[len(FileHeaderStructDecrypt) - 1]
	FileHeaderStructDecrypt = FileHeaderStructDecrypt[:(len(FileHeaderStructDecrypt) - int(LastByte))]
	err = json.Unmarshal(FileHeaderStructDecrypt, fileHeaderptr)
	if err != nil {
		return nil, err
	}
	var page FileDataPage
	pageptr := &page
	var derivedPageKeys []byte
	for i := 0; i < fileHeaderptr.FileLength; i++ {
		pageStructAndMac, oookk := userlib.DatastoreGet(fileHeaderptr.PageUUIDS[i])
		_ = oookk
		derivedPageKeys, err = userlib.HashKDF(fileHeaderptr.PagePrimaryKeys[i], []byte("derivedpagekeys"))
		if len(pageStructAndMac) < 64 {
			return nil, errors.New(strings.ToTitle("Integrity compromised."))
		}
		ActualPageMac := pageStructAndMac[:64]
		SupposedHmac, err = userlib.HMACEval(derivedPageKeys[16:32], pageStructAndMac[64:])
		if err != nil {
			return nil, err
		}
		if !userlib.HMACEqual(ActualPageMac, SupposedHmac) {
			return nil, errors.New(strings.ToTitle("User can't be authenticated or integrity compromised."))
		}
		//Decrypt, depad, and unmarshal data page.
		PageStructDecrypt := userlib.SymDec(derivedPageKeys[:16], pageStructAndMac[64:])
		LastByte = PageStructDecrypt[len(PageStructDecrypt) - 1]
		PageStructDecrypt = PageStructDecrypt[:(len(PageStructDecrypt) - int(LastByte))]
		err = json.Unmarshal(PageStructDecrypt, pageptr)
		if err != nil {
			return nil, err
		}
		dataBytes = append(dataBytes, []byte(pageptr.FileData)...)
	}
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
