package client

///////////////////////////////////////////////////
//                                               //
// Everything in this file will NOT be graded!!! //
//                                               //
///////////////////////////////////////////////////

// In this unit tests file, you can write white-box unit tests on your implementation.
// These are different from the black-box integration tests in client_test.go,
// because in this unit tests file, you can use details specific to your implementation.

// For example, in this unit tests file, you can access struct fields and helper methods
// that you defined, but in the integration tests (client_test.go), you can only access
// the 8 functions (StoreFile, LoadFile, etc.) that are common to all implementations.

// In this unit tests file, you can write InitUser where you would write client.InitUser in the
// integration tests (client_test.go). In other words, the "client." in front is no longer needed.

import (
	"strconv"
	"testing"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	_ "encoding/hex"
	"encoding/json"

	_ "errors"

	. "github.com/onsi/ginkgo/v2"

	. "github.com/onsi/gomega"

	_ "strconv"

	_ "strings"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Unit Tests")
}

var _ = Describe("Client Unit Tests", func() {

	BeforeEach(func() {
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Unit Tests", func() {
		Specify("Basic Test: Check that the Username field is set for a new user", func() {
			userlib.DebugMsg("Initializing user Alice.")
			// Note: In the integration tests (client_test.go) this would need to
			// be client.InitUser, but here (client_unittests.go) you can write InitUser.
			alice, err := InitUser("alice", "password")
			Expect(err).To(BeNil())

			// Note: You can access the Username field of the User struct here.
			// But in the integration tests (client_test.go), you cannot access
			// struct fields because not all implementations will have a username field.
			Expect(alice.Username).To(Equal("alice"))
		})

		Specify("Added Test: Testing login with tampered user", func() {
			userlib.DebugMsg("Initializing user Alice.")
			_, err := InitUser("alice", "password")
			Expect(err).To(BeNil())

			// Tamper with alice
			var userHashUUID uuid.UUID
			userHashUUID, _ = uuid.FromBytes(userlib.Hash([]byte("alice"))[:16])
			userWrapper, _ := userlib.DatastoreGet(userHashUUID)

			userWrapper[10] = 1 ^ userWrapper[10]
			userlib.DatastoreSet(userHashUUID, userWrapper)

			userlib.DebugMsg("Getting user Alice with correct password.")
			_, err = GetUser("alice", "password")
			Expect(err).ToNot(BeNil())
		})

		Specify("Added Test: Testing login with forged user", func() {
			userlib.DebugMsg("Initializing user Alice.")
			_, err := InitUser("alice", "password")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Alicep.")
			_, err = InitUser("alicep", "assword")
			Expect(err).To(BeNil())

			alicepUUID, _ := uuid.FromBytes(userlib.Hash([]byte("alicep"))[:16])
			alicep, _ := userlib.DatastoreGet(alicepUUID)
			aliceUUID, _ := uuid.FromBytes(userlib.Hash([]byte("alice"))[:16])
			userlib.DatastoreSet(aliceUUID, alicep)

			userlib.DebugMsg("Getting user Alice with incorrect password 'assword'.")
			_, err = GetUser("alice", "assword")
			Expect(err.Error()).To(Equal("Failed to retrieve the user struct: Struct has been tampered with: crypto/rsa: verification error"))
		})

		// use random bits for keys
		Specify("Added Test: Replace file key", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err := InitUser("alice", "password")
			Expect(err).To(BeNil())

			err = alice.StoreFile("aliceFile", []byte("Hello World"))
			Expect(err).To(BeNil())

			// alice can read her file initially
			filecontent, err := alice.LoadFile("aliceFile")
			Expect(err).To(BeNil())
			Expect(filecontent).To(Equal([]byte("Hello World")))

			fileUUID, err := NameFileUUID("aliceFile", "alice")
			var nameFile NameFile
			tagKey, err := userlib.HashKDF(alice.sourceKey, []byte("aliceFile"))
			Expect(err).To(BeNil())

			err = UnwrapStruct(fileUUID, &nameFile, "HMAC", tagKey, "None", "")
			Expect(err).To(BeNil())

			data, ok := userlib.DatastoreGet(nameFile.HeaderPtr)
			Expect(ok).To(Equal(true))

			var wrapper Wrapper
			err = json.Unmarshal(data, &wrapper)
			Expect(err).To(BeNil())

			var header HeaderFile
			err = json.Unmarshal(wrapper.EncryptedObj, &header)
			Expect(err).To(BeNil())

			fileKey := userlib.RandomBytes(16)

			// forge header file
			publicKey, ok := userlib.KeystoreGet("alice")
			Expect(ok).To(Equal(true))

			encKey, err := userlib.PKEEnc(publicKey, fileKey)
			Expect(err).To(BeNil())
			header.EncryptedFileKey = encKey

			tempKey, err := userlib.HashKDF(fileKey, []byte("OwnerUsername"))
			Expect(err).To(BeNil())
			byteOwner, err := json.Marshal("alice")
			Expect(err).To(BeNil())
			encOwner := userlib.SymEnc(tempKey[:16], userlib.RandomBytes(16), byteOwner)
			header.EncryptedOwner = encOwner

			tempKey, err = userlib.HashKDF(fileKey, []byte("counter"))
			Expect(err).To(BeNil())
			encCounter := userlib.SymEnc(tempKey[:16], userlib.RandomBytes(16), []byte(strconv.Itoa(1)))
			header.EncryptedCounter = encCounter

			// Wrap and store HeaderFile
			tagKey, err = userlib.HashKDF(fileKey, []byte("header"))
			Expect(err).To(BeNil())

			err = WrapStruct(header, nameFile.HeaderPtr, "HMAC", tagKey, "None", 0)
			Expect(err).To(BeNil())

			// Alice now tries to read her file
			filecontent, err = alice.LoadFile("aliceFile")
			Expect(err).ToNot(BeNil())
		})

		// General fuzz testing plan: use some combination of userlib calls such that each type of struct is created.
		// unmarshal the wrapper, store the tag
		// then unwrap the struct, modify a value, rewrap it
		// unmarshal the wrapper, write the old tag, and remarshal
		Specify("Added Test: FUZZ Testing", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err := InitUser("alice", "password")
			Expect(err).To(BeNil())

			// Get Alice's tag
			var wrapper Wrapper
			var userHashUUID uuid.UUID
			userHashUUID, err = uuid.FromBytes(userlib.Hash([]byte(alice.Username))[:16])
			data, ok := userlib.DatastoreGet(userHashUUID)
			Expect(ok).To(BeTrue())
			json.Unmarshal(data, &wrapper)
			tag := wrapper.Tag

			// Modify and rewrap Alice
			alice.Salt = userlib.RandomBytes(16)
			tempKey, err := userlib.HashKDF(alice.sourceKey, []byte("UserDataEncryption"))
			WrapStruct(alice, userHashUUID, "Signature", alice.SignKey, "Symmetric", tempKey)

			// Return the previous tag
			data, ok = userlib.DatastoreGet(userHashUUID)
			json.Unmarshal(data, &wrapper)
			wrapper.Tag = tag
			data, err = json.Marshal(wrapper)
			userlib.DatastoreSet(userHashUUID, data)

			// Check that GetUser doesn't work
			alice2, err := GetUser("alice", "password")
			Expect(err).ToNot(BeNil())
			Expect(alice2).To(BeNil())
		})

	})
})
