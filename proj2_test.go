package proj2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/cs161-staff/userlib"
	"github.com/google/uuid"
	_ "github.com/google/uuid"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

//TODO: 
/*test all: do the file moving forcing you to check hashmap for updated uuid and keys
test store/load/append: not owner, check invitations, corrupt invitations
*/

func TestInit(t *testing.T) {
	clear()

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	//t.Log("Got user", u)
	_ = u
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}


func TestInitErrorOne(t *testing.T) {
	clear()

	userlib.SetDebugStatus(true)

	_, er := InitUser("alice", "fubar")
	if er != nil {
		t.Error("Failed to initialize user", er)
		return
	}
	_, er = InitUser("alice", "ffff")
	if er == nil {
		t.Error("alice is duplicate and should error", er)
		return
	}
}

func TestInitErrorTwo(t *testing.T) {
	clear()

	userlib.SetDebugStatus(true)

	_, er := InitUser("", "hi")
	if er == nil {
		t.Error("empty usernames are not allowed and should error", er)
		return
	}
	_, er = InitUser("hi", "")
	if er == nil {
		t.Error("empty passwords are not allowed and should error", er)
		return
	}
}

func TestGetUser(t *testing.T) {
	clear()
	userlib.SetDebugStatus(true)

	user1, er := InitUser("alice", "fubar")
	if er != nil {
		t.Error("Failed to initialize user", er)
		return
	}
	user2, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get user", err)
		return
	}
	if !reflect.DeepEqual(user1, user2) {
		t.Error("Failed to get same user", user1, user2)
		return
	}
}

func TestGetUserError1(t *testing.T) {
	clear()
	userlib.SetDebugStatus(true)

	_, er := InitUser("alice", "fubar")
	if er != nil {
		t.Error("Failed to initialize user", er)
		return
	}
	u, err := GetUser("bob", "fubar")
	_ = u
	if err == nil {
		t.Error("bob doesn't exist and should error", err)
		return
	}
}

func TestGetUserError2(t *testing.T) {
	clear()
	userlib.SetDebugStatus(true)

	_, er := InitUser("alice", "fubar")
	if er != nil {
		t.Error("Failed to initalize user", er)
		return
	}
	u, err := GetUser("alice", "goobar")
	_ = u
	if err == nil {
		t.Error("alice log in is unathenticated and should error", err)
		return
	}
}

func TestGetUserError3(t *testing.T) {
	clear()
	userlib.SetDebugStatus(true)

	u, er := InitUser("alice", "fubar")
	if er != nil {
		t.Error("Failed to initalize user", er)
		return
	}

	UserID, _:= uuid.FromBytes(userlib.Hash([]byte(u.Username))[:16])
	userlib.DatastoreSet(UserID, []byte("garbage"))

	u, err := GetUser("alice", "fubar")
	if err == nil {
		t.Error("alice user corrupted and should error", err)
		return
	}
}

func TestStoreFile1(t *testing.T) {
	clear()

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	f1 := []byte("file1")
	err = u.StoreFile("file1", f1)
	if err != nil {
		t.Error("Failed to store file", err)
		return
	}

	f2 := []byte("file2")
	err = u.StoreFile("file2", f2)
	if err != nil {
		t.Error("Failed to store file", err)
		return
	}

	f3 := []byte("file1New")
	err = u.StoreFile("file1", f3)
	if err != nil {
		t.Error("Failed to store file", err)
		return
	}

	f4 := []byte("file2New")
	err = u.StoreFile("file2", f4)
	if err != nil {
		t.Error("Failed to store file", err)
		return
	}
}

func TestStoreFileError(t *testing.T) {
	clear()
	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	ds := userlib.DatastoreGetMap()
	ds_orig := make(map[uuid.UUID][]byte)
	for k, v := range ds {
		ds_orig[k] = v
	}

	f1 := []byte("file1")
	err = u.StoreFile("file1", f1)
	if err != nil {
		t.Error("Failed to store file", err)
		return
	}

	ds = userlib.DatastoreGetMap()
	changedElem := uuid.New()
	for k, _ := range ds {
		if !reflect.DeepEqual(ds[k], ds_orig[k])  {
			changedElem = k
		}
	}
	userlib.DatastoreSet(changedElem, []byte("garbage"))

	f3 := []byte("file1New")
	err = u.StoreFile("file1", f3)
	if err == nil {
		t.Error("File header has been corrupted. Should error", err)
		return
	}
}

func TestStoreFileError2(t *testing.T) {
	clear()
	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	ds := userlib.DatastoreGetMap()
	ds_orig := make(map[uuid.UUID][]byte)
	for k, v := range ds {
		ds_orig[k] = v
	}

	f1 := []byte("file1")
	err = u.StoreFile("file1", f1)
	if err != nil {
		t.Error("Failed to store file", err)
		return
	}

	ds = userlib.DatastoreGetMap()
	changedElem := uuid.New()
	for k, _ := range ds {
		if !reflect.DeepEqual(ds[k], ds_orig[k])  {
			changedElem = k
		}
	}
	userlib.DatastoreSet(changedElem, []byte("garbageeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"))

	f3 := []byte("file1New")
	err = u.StoreFile("file1", f3)
	if err == nil {
		t.Error("File header has been corrupted. Should error", err)
		return
	}
}


func TestAppendFile1(t *testing.T) {
	clear()
	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	f1 := []byte("file1")
	err = u.StoreFile("file1", f1)
	if err != nil {
		t.Error("Failed to store file", err)
		return
	}

	f2 := []byte("file2")
	err = u.StoreFile("file2", f2)
	if err != nil {
		t.Error("Failed to store file", err)
		return
	}

	f3 := []byte("file1New")
	err = u.AppendFile("file1", f3)
	if err != nil {
		t.Error("Failed to store file", err)
		return
	}

	f4 := []byte("file2New")
	err = u.AppendFile("file2", f4)
	if err != nil {
		t.Error("Failed to store file", err)
		return
	}
	/*

	var fileHeader FileHeader
	var fileHeaderptr = &fileHeader
	fileHeadLocation := u.FileNameToMetaData[string(userlib.Hash([]byte("file1")))]
	fileHeaderStructAndMac, _ := userlib.DatastoreGet(fileHeadLocation.HeaderUuid)
	fileHeaderPrimaryKey := fileHeadLocation.HeaderPrimaryKey

	derivedFileHeaderKeys, erro := userlib.HashKDF(fileHeaderPrimaryKey, []byte("derivedfileheaderkeys"))
	_ = erro

	//Decrypt, depad, and unmarshal fileheader.
	FileHeaderStructDecrypt := userlib.SymDec(derivedFileHeaderKeys[:16], fileHeaderStructAndMac[64:])
	LastByte := FileHeaderStructDecrypt[len(FileHeaderStructDecrypt) - 1]
	FileHeaderStructDecrypt = FileHeaderStructDecrypt[:(len(FileHeaderStructDecrypt) - int(LastByte))]
	err = json.Unmarshal(FileHeaderStructDecrypt, fileHeaderptr)
	if err != nil {
		t.Error("Failed", err)
		return
	}
	if fileHeaderptr.FileLength != 2 {
		t.Error("Failed length check", err)
		return
	}

	f3 = []byte("file1New")
	err = u.StoreFile("file1", f3)
	if err != nil {
		t.Error("Failed to store file", err)
		return
	}

	fileHeadLocation = u.FileNameToMetaData[string(userlib.Hash([]byte("file1")))]
	fileHeaderStructAndMac, _ = userlib.DatastoreGet(fileHeadLocation.HeaderUuid)
	fileHeaderPrimaryKey = fileHeadLocation.HeaderPrimaryKey

	derivedFileHeaderKeys, erro = userlib.HashKDF(fileHeaderPrimaryKey, []byte("derivedfileheaderkeys"))
	_ = erro

	//Decrypt, depad, and unmarshal fileheader.
	FileHeaderStructDecrypt = userlib.SymDec(derivedFileHeaderKeys[:16], fileHeaderStructAndMac[64:])
	LastByte = FileHeaderStructDecrypt[len(FileHeaderStructDecrypt) - 1]
	FileHeaderStructDecrypt = FileHeaderStructDecrypt[:(len(FileHeaderStructDecrypt) - int(LastByte))]
	err = json.Unmarshal(FileHeaderStructDecrypt, fileHeaderptr)
	if err != nil {
		t.Error("Failed", err)
		return
	}
	if fileHeaderptr.FileLength != 1 {
		t.Error("Failed length check", err)
		return
	}
	*/
}

func TestApendFileError1(t *testing.T) {
	clear()
	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	f1 := []byte("file1")
	err = u.StoreFile("file1", f1)
	if err != nil {
		t.Error("Failed to store file", err)
		return
	}

	f3 := []byte("file1New")
	err = u.AppendFile("file3", f3)
	if err == nil {
		t.Error("User doesn't own file, should error", err)
		return
	}
}

func TestAppendFileError2(t *testing.T) {
	clear()
	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	ds := userlib.DatastoreGetMap()
	ds_orig := make(map[uuid.UUID][]byte)
	for k, v := range ds {
		ds_orig[k] = v
	}

	f1 := []byte("file1")
	err = u.StoreFile("file1", f1)
	if err != nil {
		t.Error("Failed to store file", err)
		return
	}

	ds = userlib.DatastoreGetMap()
	changedElem := uuid.New()
	for k, _ := range ds {
		if !reflect.DeepEqual(ds[k], ds_orig[k])  {
			changedElem = k
		}
	}
	userlib.DatastoreSet(changedElem, []byte("garbage"))

	f3 := []byte("file1New")
	err = u.AppendFile("file1", f3)
	if err == nil {
		t.Error("File header has been corrupted. Should error", err)
		return
	}
}

func TestAppendFileError3(t *testing.T) {
	clear()
	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	ds := userlib.DatastoreGetMap()
	ds_orig := make(map[uuid.UUID][]byte)
	for k, v := range ds {
		ds_orig[k] = v
	}

	f1 := []byte("file1")
	err = u.StoreFile("file1", f1)
	if err != nil {
		t.Error("Failed to store file", err)
		return
	}

	ds = userlib.DatastoreGetMap()
	changedElem := uuid.New()
	for k, _ := range ds {
		if !reflect.DeepEqual(ds[k], ds_orig[k])  {
			changedElem = k
		}
	}
	userlib.DatastoreSet(changedElem, []byte("garbageeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"))

	f3 := []byte("file1New")
	err = u.AppendFile("file1", f3)
	if err == nil {
		t.Error("File header has been corrupted. Should error", err)
		return
	}
}

func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}

func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var accessToken uuid.UUID

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	accessToken, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
}
