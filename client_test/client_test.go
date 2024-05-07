package client_test

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables
// ================================================
const defaultPassword = "password"

// const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// Helper function to measure bandwidth of a particular operation
var measureBandwidth = func(probe func()) (bandwidth int) {
	before := userlib.DatastoreGetBandwidth()
	probe()
	after := userlib.DatastoreGetBandwidth()
	return after - before
}

var _ = Describe("Client Tests", func() {

	var alice *client.User
	var bob *client.User
	var charles *client.User
	// var doris *client.User
	// var eve *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Added Test: Testing login on nonexistent user.", func() {
			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Added Test: Testing login with invalid credentials", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", "password")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice with incorrect password.")
			aliceLaptop, err = client.GetUser("alice", "wrongPassword")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Getting user alicepass, word.")
			aliceLaptop, err = client.GetUser("alicepass", "word")
			Expect(err).ToNot(BeNil())
		})

		Specify("Added Test: Testing InitUser error cases.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", "password")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing Alice fails when called again.")
			aliceLaptop, err = client.InitUser("alice", "password2")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Initializing empty name fails")
			aliceDesktop, err = client.InitUser("", "password")
			Expect(err).ToNot(BeNil())
		})

		Specify("Added Test: Testing Single User Store/Load.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Specify("Added Test: Testing File Operations Error Handling", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading a non-existent file fails")
			_, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			datastoreMap := userlib.DatastoreGetMap()
			for addr := range datastoreMap {
				userlib.DatastoreSet(addr, []byte(contentOne))
			}

			userlib.DebugMsg("Loading a Alice's tampered file fails")
			content, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
			Expect(content).To(BeNil())

			userlib.DebugMsg("Appending Alice's tampered file fails")
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			// Set up next set of errors
			userlib.KeystoreClear()
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("Bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading Alice's file returns content from entire file")
			content, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("Bitcoin is Nick's favorite digital "))) // 8th byte should be B if all went correct

			userlib.DebugMsg("Bob can't load Alice's file")
			content, err = bob.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Added Advanced Test: Testing login from multiple dveices.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice (laptop).")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice (phone).")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice (ipad).")
			aliceIpad, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice (smart fridge).")
			aliceSmartFridge, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice (phone) storing file %s with content: %s", aliceFile, "123")
			err = alicePhone.StoreFile(aliceFile, []byte("123"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice (smart fridge) reads the file")
			var content []byte
			content, err = aliceSmartFridge.LoadFile(aliceFile)
			userlib.DebugMsg("Alice (smart fridge) reads: %s", content)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("123")))

			userlib.DebugMsg("Alice (ipad) appending to file %s, content: %s", aliceFile, "456")
			err = aliceIpad.AppendToFile(aliceFile, []byte("456"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice (laptop) appending to file %s, content: %s", aliceFile, "789")
			err = aliceLaptop.AppendToFile(aliceFile, []byte("789"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice (smart fridge) reads the file")
			content, err = aliceSmartFridge.LoadFile(aliceFile)
			userlib.DebugMsg("Alice (smart fridge) reads: %s", content)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("123456789")))
		})

		Specify("Added Test: Efficiency testing.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, "123")
			err = alice.StoreFile(aliceFile, []byte("123"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice appending to file %s, content: %s", aliceFile, "456")
			bw1 := measureBandwidth(func() {
				alice.AppendToFile(aliceFile, []byte("456"))
			})

			userlib.DebugMsg("Alice appending to file %s, content: %s", aliceFile, "456")
			bw2 := measureBandwidth(func() {
				alice.AppendToFile(aliceFile, []byte("456"))
			})

			Expect(bw1).To(Equal(bw2))

			userlib.DebugMsg("Alice appending to file %s, content: %s", aliceFile, "456456456456")
			bw1 = measureBandwidth(func() {
				alice.AppendToFile(aliceFile, []byte("456456456456"))
			})
			userlib.DebugMsg("Alice appending to file %s, content: %s", aliceFile, "456456456456")
			bw2 = measureBandwidth(func() {
				alice.AppendToFile(aliceFile, []byte("456456456456"))
			})

			Expect(bw1).To(Equal(bw2))

			bob, err := client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charlie, err := client.InitUser("charlie", defaultPassword)
			Expect(err).To(BeNil())

			david, err := client.InitUser("david", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for charlie.")
			invite2, err := alice.CreateInvitation(aliceFile, "charlie")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charlie accepting invite from Alice under filename %s.", bobFile)
			err = charlie.AcceptInvitation("alice", invite2, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("charlie creating invite for david.")
			invite3, err := charlie.CreateInvitation(bobFile, "david")
			Expect(err).To(BeNil())

			userlib.DebugMsg("David accepting invite from Charlie under filename %s.", bobFile)
			err = david.AcceptInvitation("charlie", invite3, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice appending to file %s, content: %s", aliceFile, "456456456456")
			bw2 = measureBandwidth(func() {
				alice.AppendToFile(aliceFile, []byte("456456456456"))
			})

			Expect(bw1).To(Equal(bw2))
		})

		Specify("Added Basic Test: Testing Create/Accept Invitation.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte("hi im alice"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob reads the file he just accepted")
			var content []byte
			content, err = bob.LoadFile(bobFile)
			userlib.DebugMsg("Bob reads: %s", content)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("hi im alice")))

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, ". hi im bob")
			err = bob.AppendToFile(bobFile, []byte(". hi im bob"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice reading the file that bob appended to")
			content, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("hi im alice. hi im bob")))
		})

		Specify("Added Basic Test: Testing Create/Accept Invitation Error Cases.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte("hi im alice"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice can't create invite for invalid filename")
			invite, err := alice.CreateInvitation("AliceFile2.txt", "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("alice can't create invite for invalid user")
			invite, err = alice.CreateInvitation("AliceFile2.txt", "charles")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob calling AcceptInvitation on the wrong user should fail")
			err = bob.AcceptInvitation("charles", invite, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Charles can't call AcceptInvitation on the invitation to Bob")
			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob can't accept invite when invitation has been tampered")
			userlib.DatastoreDelete(invite)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can append the file.")
			alice.AppendToFile(aliceFile, []byte("Hi"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can append the file.")
			charles.AppendToFile(charlesFile, []byte("Bye"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can append the file.")
			bob.AppendToFile(bobFile, []byte("Hi"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can load the file.")
			alice.AppendToFile(aliceFile, []byte("Again"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + "HiByeHiAgain")))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("Added Test: Revoked Error cases", func() {
			userlib.DebugMsg("Initializing users Alice and Bob and file Alice.txt")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates invitation for bob, then revokes bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob can't acceptInvitation after being revoked")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice can't revoke access on a garbage file")
			err = alice.RevokeAccess("GarbageFile.txt", "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Added Test: Revoked user attacks", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, Charlie, and David")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			david, err := client.InitUser("david", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			davidFile := "DavidsFile"

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite1, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for David for file %s, and David accepting invite under name %s.", aliceFile, davidFile)
			invite2, err := alice.CreateInvitation(aliceFile, "david")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite1, bobFile)
			Expect(err).To(BeNil())

			err = david.AcceptInvitation("alice", invite2, davidFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that David can load the file.")
			data, err = david.LoadFile(davidFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err := bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that David can still load the file.")
			data, err = david.LoadFile(davidFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob tries accepting the invite again to regain access.")
			err = bob.AcceptInvitation("alice", invite1, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob tries creating an invite for Charles.")
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Charles tries accepting the invite again to regain access.")
			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Bob/Charles still do not have access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Added Test: Datastore adversary tampers with user", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, Charlie, and David")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Delete Alice")
			userlib.DatastoreClear()

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Added Test: Datastore adversary tampers with file", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, Charlie, and David")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			content, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Delete everything")
			userlib.DatastoreClear()

			userlib.DebugMsg("Fetch file")
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})
	})
})
