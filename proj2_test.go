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
//test SHARE, REVOKE + other things (including call receive after revocation), SHARE
//TEST SHOE EXAMPLE TEST POINTER CLEARING 
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

func TestAppendFile2(t *testing.T) {
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

func TestSpecExample1 (t *testing.T) {
	clear() 
	f1 := []byte("content")
	f2 := []byte("different content")

	// Alice and Bob each start a users session by authenticating to the client.
	alice_session_1, _ := InitUser("user_alice", "password1")
	bob_session_1, _ := InitUser("user_bob", "password2")

	// Alice stores byte slice f1 with name "filename" and Bob stores byte slice
	// f2 also with name "filename".
	alice_session_1.StoreFile("filename", f1)
	bob_session_1.StoreFile("filename", f2)
	//t.Error((len((*(bob_session_1.FileNameToMetaData)))))
	bob_session_1.StoreFile("filename2", f2)
	//t.Error((len((*(bob_session_1.FileNameToMetaData)))))

	// Alice and Bob each confirm that they can load the file they previously
	// stored and that the file contents is the same.

	f1_loaded, _ := alice_session_1.LoadFile("filename")
	f2_loaded, _ := bob_session_1.LoadFile("filename")
	//t.Error((len((*(bob_session_1.FileNameToMetaData)))))

	if !reflect.DeepEqual(f1, f1_loaded) {
		t.Error("file contents are different.", f1, f1_loaded)
		return
	}
	if !reflect.DeepEqual(f2, f2_loaded) {
		t.Error("file contents are different.", f2, f2_loaded)
		return
	}

	// Alice gets an error when trying to load a file that does not exist in her
	// namespace.
	_, err := alice_session_1.LoadFile("nonexistent")
	if err == nil {
		t.Error("Alice downloaded nonexistent. Should error")
		return
	}

	// Bob creates a second user session by authenticating to the client again.
	bob_session_3, err := GetUser("user_bob", "password2")
	_ = bob_session_3
	if err != nil {
		t.Error("error", err)
		return
	}
	bob_session_2, err := GetUser("user_bob", "password2")
	if err != nil {
		t.Error("error", err)
		return
	}

	bob_s2, err := bob_session_2.LoadFile("filename")
	//t.Error((len((*(bob_session_1.FileNameToMetaData)))))
	if err != nil || !reflect.DeepEqual(bob_s2, f2) {
		t.Error("s2 cannot load s1 file", err)
		return
	}
	bob_s2, err = bob_session_2.LoadFile("filename2")
	//t.Error((len((*(bob_session_1.FileNameToMetaData)))))
	if err != nil || !reflect.DeepEqual(bob_s2, f2) {
		t.Error("s2 cannot load s1 file", err)
		return
	}
	//t.Error(bob_session_1)
	//t.Error(bob_session_2)
	//t.Error(bob_session_3)
	// t.Error((len((*(bob_session_1.FileNameToMetaData)))))
	// t.Error((len((*(bob_session_2.FileNameToMetaData)))))
	// t.Error((len((*(bob_session_3.FileNameToMetaData)))))

	// for key, value := range (*(bob_session_1.FileNameToMetaData)) {
	// 	t.Error("Key:", key, "Value:", value)
	// }
	// for key, value := range (*(bob_session_2.FileNameToMetaData)) {
	// 	t.Error("Key:", key, "Value:", value)
	// }
	// for key, value := range (*(bob_session_3.FileNameToMetaData)) {
	// 	t.Error("Key:", key, "Value:", value)
	// }

	// Bob stores byte slice f2 with name "newfile" using his second user
	// session.
	bob_session_2.StoreFile("newfile", f2)
	// t.Error((len((*(bob_session_1.FileNameToMetaData)))))
	// t.Error((len((*(bob_session_2.FileNameToMetaData)))))
	// t.Error((len((*(bob_session_3.FileNameToMetaData)))))


	// Bob loads "newfile" using his first user session. Notice that Bob does
	// not need to reauthenticate. File changes must be available to all active
	// sessions for a given user.

	f2_newfile, err := bob_session_1.LoadFile("newfile")
	if err != nil || !reflect.DeepEqual(f2_newfile, f2) {
		t.Error("error", err)
		return
	}
	//t.Error((len((*(bob_session_1.FileNameToMetaData)))))
	
	// f2_newfile, err = bob_session_2.LoadFile("newfile")
	// if err != nil {
	// 	t.Error("error", err)
	// }

	// if reflect.DeepEqual(f2, f2_newfile) {
	// 	t.Error("f2 and f2_newfile are equal.")
	// }
	
	f2_newfile, err = bob_session_3.LoadFile("newfile")
	if err != nil || !reflect.DeepEqual(f2_newfile, f2) {
		t.Error("error", err)
		return
	}

	if !reflect.DeepEqual(f2, f2_newfile) {
		t.Error("file contents are different.", f2_newfile, f2)
		return
	}
}

func TestStoreAppendLoadFile1(t *testing.T) {
	clear()
	// You can set this to false!
	userlib.SetDebugStatus(true)

	alice_session_1, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	f1 := []byte("file1part1")
	err = alice_session_1.StoreFile("file1", f1)
	if err != nil {
		t.Error("Failed to store file", err)
		return
	}

	f1p2 := []byte("file1part2")
	err = alice_session_1.AppendFile("file1", f1p2)
	if err != nil {
		t.Error("Failed to append file", err)
		return
	}

	f1_loaded, _ := alice_session_1.LoadFile("file1")
	f1_loaded_expected := []byte("file1part1file1part2")

	if !reflect.DeepEqual(f1_loaded, f1_loaded_expected) {
		t.Error("file contents are different", f1_loaded, f1_loaded_expected)
		return
	}

	f1new := []byte("file1overwrite")
	err = alice_session_1.StoreFile("file1", f1new)
	if err != nil {
		t.Error("Failed to store file", err)
		return
	}
	
	f1_loaded_new, _ := alice_session_1.LoadFile("file1")
	if !reflect.DeepEqual(f1new, f1_loaded_new) {
		t.Error("file contents are different", f1_loaded, f1_loaded_new)
		return
	}
}

func TestStoreAppendLoadSessions (t *testing.T) {
	clear()
	// You can set this to false!
	userlib.SetDebugStatus(true)

	alice_session_1, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	f1 := []byte("file1part1")
	err = alice_session_1.StoreFile("file1", f1)
	if err != nil {
		t.Error("Failed to store file", err)
		return
	}

	alice_session_2, erro := GetUser("alice", "fubar")
	if erro != nil {
		t.Error("failed to get user", err)
		return
	}

	f1p2 := []byte("file1part2")
	err = alice_session_2.AppendFile("file1", f1p2)
	if err != nil {
		t.Error("Failed to append file", err)
		return
	}

	f1_loaded, _ := alice_session_1.LoadFile("file1")
	f1_loaded_expected := []byte("file1part1file1part2")

	if !reflect.DeepEqual(f1_loaded, f1_loaded_expected) {
		t.Error("file contents are different", f1_loaded, f1_loaded_expected)
		return
	}

	f1new := []byte("file1overwrite")
	err = alice_session_2.StoreFile("file1", f1new)
	if err != nil {
		t.Error("Failed to store file", err)
		return
	}
	
	f1_loaded_new, _ := alice_session_1.LoadFile("file1")
	if !reflect.DeepEqual(f1new, f1_loaded_new) {
		t.Error("file contents are different", f1_loaded, f1_loaded_new)
		return
	}
}

func TestLoadFileError1(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	f1 := []byte("file1")
	err = u.StoreFile("file1", f1)
	if err !=  nil {
		t.Error("couldn't store file")
		return
	}
	_, erro := u.LoadFile("filenoexist")
	if erro == nil {
		t.Error("File doesn't exist and should error", erro)
		return
	}
}

/*
func TestLoadFileCorruption(t *testing.T) {
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

	_, erro := u.LoadFile("file1")
	if erro == nil {
		t.Error("File header has been corrupted. Should error", err)
		return
	}
}


func TestUserCorruption(t *testing.T) {
	clear()
	// You can set this to false!
	userlib.SetDebugStatus(true)

	ds := userlib.DatastoreGetMap()
	ds_orig := make(map[uuid.UUID][]byte)
	for k, v := range ds {
		ds_orig[k] = v
	}

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}	

	ds = userlib.DatastoreGetMap()
	changedElem := uuid.New()
	for k, _ := range ds {
		if !reflect.DeepEqual(ds[k], ds_orig[k])  {
			changedElem = k
		}
	}

	_ = u

	f1 := []byte("nice")

	u.StoreFile("file", f1)

	userlib.DatastoreSet(changedElem, []byte("garbage"))

	_, erro := GetUser("alice", "fubar")
	if erro == nil {
		t.Error("User has been corrupted. Should error.", erro)
		return
	}
}
*/

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

func TestShare1(t *testing.T) {
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

	accessToken, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file1", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	err = u2.AppendFile("file1", []byte(" yes"))
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	v2 = []byte("This is a test yes")

	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	err = u2.StoreFile("file1", []byte("ok"))
	if err != nil {
		t.Error("Failed to store file", err)
	}

	v, err = u2.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download file from alice", err)
	}

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download file from alice", err)
	}

	v2 = []byte("ok")

	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
}

func TestShareReceiveError(t *testing.T) {
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

	var accessToken uuid.UUID

	u2.StoreFile("file1", []byte("mallow"))

	accessToken, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file1", "alice", accessToken)
	if err == nil {
		t.Error("Should not be able to receive since already owns file", err)
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

func TestReceiveCorruptInvitation(t *testing.T) {
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

	var accessToken uuid.UUID

	accessToken, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}

	userlib.DatastoreSet(accessToken, []byte("garbage"))

	err = u2.ReceiveFile("file1", "alice", accessToken)
	if err == nil {
		t.Error("AccessToken corrupted, should error", err)
		return
	}
}