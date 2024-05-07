package client

import (
	"encoding/json"
	"errors"
	"strconv"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

// This is the type definition for the User struct.
type User struct {
	Username     string            // Plaintext Username
	PasswordHash []byte            // Argon2Key(password, salt)
	Salt         []byte            // Random salt
	DecKey       userlib.PKEDecKey // Private DecKey
	SignKey      userlib.DSSignKey // Private SignKey
	sourceKey    []byte            // Argon2Key(password, username))
}

// Wraps an encrypted obj []byte
type Wrapper struct {
	EncryptedObj []byte // The result of calling Enc(json.marshal(someStruct))
	Tag          []byte // The tag of the above []byte
}

// Used to namespace a user's files.
// Security: HMACed with sourceKey + filename.
type NameFile struct {
	HeaderPtr uuid.UUID // Points to the user's header or auth file
}

// Stores important metadata about a file.
// Security:
//   - fileKey is encrypted with public key
//   - owner is encrypted with fileKey + "OwnerUsername"
//   - counter is encrypted with fileKey + {counter}
//
// HMACed with fileKey + "header"
type HeaderFile struct {
	InitialNode      uuid.UUID
	FinalNode        uuid.UUID
	ShareNode        uuid.UUID
	EncryptedOwner   []byte
	EncryptedFileKey []byte
	EncryptedCounter []byte    // how many nodes are in the file
	ToHeader         uuid.UUID // points to a header if this is an auth struct, NilUUID if not
}

// Sharing metadata, encrypted with file key, and signed by whoever the share node belongs to
// Security: encrypted with fileKey + purpose "EncryptShareNode". HMACed with filekey + purpose "ShareNode."
type ShareNode struct {
	SharedMap map[string]uuid.UUID // Users we shared this with (username: headerfile uuid)
}

// A node in the file that points to content
// Security: encrypted with fileKey. HMACed with fileKey + "Node" + {counter}.
type FileNode struct {
	NextNode uuid.UUID
	Content  uuid.UUID
}

// A node that stores the actual content
// Security: encrypted with fileKey + "EncryptFile". HMACed with fileKey + "Content" + {counter}.
type ContentChunk struct {
	Content []byte // The result of calling Enc(json.marshal(someStruct))
}

func NilUUID() uuid.UUID {
	var nilUUID uuid.UUID
	nilUUID, _ = uuid.FromBytes([]byte("0"))
	return nilUUID
}

// Returns UUID(H(H(filename) || username))
func NameFileUUID(filename string, username string) (u uuid.UUID, err error) {
	return uuid.FromBytes(userlib.Hash(append(userlib.Hash([]byte(filename)), []byte(username)...))[:16])
}

// Given the address of a wrapper in datastore, unwrap it, check the tag, and decrypt the object
// The decrypted object will be placed at `address`
// tagType: "HMAC" or "Signature"
// decryptionType: "RSA", "Symmetric", or "None"
// If decryptionType is none any value for the decryptionKey is okay
func UnwrapStruct(WrapperUUID uuid.UUID, address any,
	tagType string, tagKey any,
	decryptionType string, decryptionKey any) (err error) {
	var wrapper Wrapper
	var decryptedBytes []byte

	// Fetch from datastore
	wrapperBytes, exists := userlib.DatastoreGet(WrapperUUID)
	if !exists {
		return errors.New("User has been deleted")
	}

	// Unmarshal the wrapper struct
	err = json.Unmarshal(wrapperBytes, &wrapper)
	if err != nil {
		return errors.New("Failed to unmarshal the wrapperBytes: " + err.Error())
	}

	// Check if the wrapper struct has been tampered with using the HMAC or signature
	if tagType == "HMAC" {
		hmacKey, ok := tagKey.([]byte)
		if !ok {
			return errors.New("HMAC key is nil or incorrectly typed: " + err.Error())
		}
		var HMACOutput []byte
		HMACOutput, err = userlib.HMACEval(hmacKey[:16], wrapper.EncryptedObj)
		if err != nil {
			return errors.New("Failed to generate wrapper HMAC: " + err.Error())
		}
		if !userlib.HMACEqual(HMACOutput, wrapper.Tag) {
			return errors.New("struct has been tampered with")
		}
	} else if tagType == "Signature" {
		verifyKey, ok := tagKey.(userlib.DSVerifyKey)
		if !ok {
			return errors.New("Verify key is nil or incorrectly typed: " + err.Error())
		}
		err = userlib.DSVerify(verifyKey, wrapper.EncryptedObj, wrapper.Tag)
		if err != nil {
			return errors.New("Struct has been tampered with: " + err.Error())
		}
	}

	// Decrypt the struct
	if decryptionType == "RSA" {
		rsaKey, ok := decryptionKey.(userlib.PKEDecKey)
		if !ok {
			return errors.New("RSA key is nil or incorrectly typed: " + err.Error())
		}

		decryptedBytes, err = userlib.PKEDec(rsaKey, wrapper.EncryptedObj)
		if err != nil {
			return errors.New("Failed to decrypt content with RSA key: " + err.Error())
		}
	} else if decryptionType == "Symmetric" {
		symKey, ok := decryptionKey.([]byte)
		if !ok {
			return errors.New("Symmetric key is nil or incorrectly typed: " + err.Error())
		}

		decryptedBytes = userlib.SymDec(symKey[:16], wrapper.EncryptedObj)
	} else {
		decryptedBytes = wrapper.EncryptedObj
	}

	err = json.Unmarshal(decryptedBytes, address)
	return err
}

// Given a struct: marshal it, generate a tag, populate and serialize the wrapper into Datastore at uuid
// tagType: either "HMAC" or "Signature"
// encryptionType: "RSA", "Symmetric", or "None"
// Any value for encryptionKey is value in the case of "None" type encryption
func WrapStruct(data any, uuid uuid.UUID,
	tagType string, tagKey any,
	encryptionType string, encryptionKey any) (err error) {
	var encryptedContent []byte
	var wrappedStruct Wrapper

	// marshal the object
	dataBytes, err := json.Marshal(data)

	// encrypt
	if encryptionType == "RSA" {
		rsaKey, ok := encryptionKey.(userlib.PKEEncKey)
		if !ok {
			return errors.New("RSA key is nil or incorrectly typed: " + err.Error())
		}

		encryptedContent, err = userlib.PKEEnc(rsaKey, dataBytes)
		if err != nil {
			return errors.New("Failed to encrypt content with RSA key: " + err.Error())
		}
	} else if encryptionType == "Symmetric" {
		symKey, ok := encryptionKey.([]byte)
		if !ok {
			return errors.New("Symmetric key is nil or incorrectly typed: " + err.Error())
		}

		encryptedContent = userlib.SymEnc(symKey[:16], userlib.RandomBytes(16), dataBytes)
	} else {
		// do not encrypt
		encryptedContent = dataBytes
	}

	wrappedStruct.EncryptedObj = encryptedContent

	// generate tag or signature
	if tagType == "HMAC" {
		hmacKey, ok := tagKey.([]byte)
		if !ok {
			return errors.New("HMAC key is nil or incorrectly typed: " + err.Error())
		}
		wrappedStruct.Tag, err = userlib.HMACEval(hmacKey[:16], encryptedContent)
		if err != nil {
			return errors.New("Failed to generate wrapper HMAC: " + err.Error())
		}
	} else if tagType == "Signature" {
		signKey, ok := tagKey.(userlib.DSSignKey)
		if !ok {
			return errors.New("Sign key is nil or incorrectly typed: " + err.Error())
		}
		wrappedStruct.Tag, err = userlib.DSSign(signKey, encryptedContent)
		if err != nil {
			return errors.New("Failed to generate wrapper signature: " + err.Error())
		}
	}

	var wrapperBytes []byte
	wrapperBytes, err = json.Marshal(wrappedStruct)
	if err != nil {
		return errors.New("Failed to marshal wrapper struct: " + err.Error())
	}
	userlib.DatastoreSet(uuid, wrapperBytes)

	return nil
}

// Given a HeaderFile and the UUID.new() to store it at,
// encrypt the fileKey and counter, and create and wrap the HeaderFile
// NOTE: username is the username of whoever's auth struct / headerfile this belongs to
func WrapHeaderFile(headerFileUUID uuid.UUID, header HeaderFile,
	tagType string, tagKey any,
	fileKey []byte, username string, owner string, counter int) (err error) {
	var tempKey []byte

	// Encrypt file key using username's public key
	publicKey, exists := userlib.KeystoreGet(username)
	if !exists {
		return errors.New("unable to retrieve public key")
	}

	encKey, err := userlib.PKEEnc(publicKey, fileKey)
	if err != nil {
		return errors.New("Failed to encrypt file key: " + err.Error())
	}
	header.EncryptedFileKey = encKey

	// Encrypt owner string
	tempKey, err = userlib.HashKDF(fileKey, []byte("OwnerUsername"))
	if err != nil {
		return errors.New("Failed to generate owner string encryption key: " + err.Error())
	}

	byteOwner, err := json.Marshal(owner)
	if err != nil {
		return errors.New("Failed to marshal owner string: " + err.Error())
	}
	encOwner := userlib.SymEnc(tempKey[:16], userlib.RandomBytes(16), byteOwner)
	header.EncryptedOwner = encOwner

	// Encrypt counter
	tempKey, err = userlib.HashKDF(fileKey, []byte("counter"))
	if err != nil {
		return errors.New("Failed to generate counter encryption key: " + err.Error())
	}

	encCounter := userlib.SymEnc(tempKey[:16], userlib.RandomBytes(16), []byte(strconv.Itoa(counter)))
	header.EncryptedCounter = encCounter

	// Wrap and store HeaderFile
	if tagType == "HMAC" {
		tagKey, err = userlib.HashKDF(fileKey, []byte("header"))
		if err != nil {
			return errors.New("Failed to generate header file encryption key: " + err.Error())
		}

	}

	err = WrapStruct(header, headerFileUUID, tagType, tagKey, "None", 0)
	if err != nil {
		return errors.New("Failed to create header file wrapper: " + err.Error())
	}

	return err
}

// Given the UUID of a headerFile, a pointer to a header file object,
// a should you decrypt the file key boolean, a decrypted file key that
// should be garbage if the previous value is true,
// and the user's own private key if shouldDecrypt is false,
// get the headerfile wrapper from datastore, populate the fields,
// and return the decrypted file key and decrypted counter
func UnwrapHeaderFile(headerFileUUID uuid.UUID, headerAddress *HeaderFile,
	tagType string, tagKey any,
	shouldDecrypt bool, unencryptedFileKey []byte,
	userDecKey userlib.PrivateKeyType) (plaintextFileKey []byte, counter int, owner string, err error) {
	var wrapper Wrapper
	var tempKey []byte

	wrapperBytes, ok := userlib.DatastoreGet(headerFileUUID)
	if !ok {
		return nil, -1, "", errors.New("failed to retrieve Header File")
	}

	// Get headerFile Struct
	err = json.Unmarshal(wrapperBytes, &wrapper)
	if err != nil {
		return nil, -1, "", errors.New("failed to unmarshal the wrapper: " + err.Error())
	}

	err = json.Unmarshal(wrapper.EncryptedObj, headerAddress)
	if err != nil {
		return nil, -1, "", errors.New("Failed to unmarshal the header file: " + err.Error())
	}

	fileKey := unencryptedFileKey
	// Decrypt file key
	if shouldDecrypt {
		fileKey, err = userlib.PKEDec(userDecKey, (*headerAddress).EncryptedFileKey)
		if err != nil {
			return nil, -1, "", errors.New("Failed to decrypt the file key: " + err.Error())
		}
	}

	// Unwrap struct using the fileKey you just found
	if tagType == "HMAC" {
		tagKey, err = userlib.HashKDF(fileKey, []byte("header"))
		if err != nil {
			return nil, -1, "", errors.New("Failed to generate header file tag key: " + err.Error())
		}
	}

	err = UnwrapStruct(headerFileUUID, headerAddress, tagType, tagKey, "None", 0)
	if err != nil {
		return nil, -1, "", errors.New("Header wrapper error: " + err.Error())
	}

	// Decrypt counter
	tempKey, err = userlib.HashKDF(fileKey, []byte("counter"))
	if err != nil {
		return nil, -1, "", errors.New("Failed to generate counter decryption key: " + err.Error())
	}
	c := userlib.SymDec(tempKey[:16], (*headerAddress).EncryptedCounter)

	// Unmarshal the counter
	var count int
	err = json.Unmarshal(c, &count) // unwrapheaderfile places the unencrypted count in this field
	if err != nil {
		return nil, -1, "", errors.New("Failed to unmarshal the counter: " + err.Error())
	}

	// Decrypt owner string
	tempKey, err = userlib.HashKDF(fileKey, []byte("OwnerUsername"))
	if err != nil {
		return nil, -1, "", errors.New("Failed to generate owner decryption key: " + err.Error())
	}
	o := userlib.SymDec(tempKey[:16], (*headerAddress).EncryptedOwner)

	// Unmarshal the owner
	var ownerStr string
	err = json.Unmarshal(o, &ownerStr) // unwrapheaderfile places the unencrypted count in this field
	if err != nil {
		return nil, -1, "", errors.New("Failed to unmarshal the owner: " + err.Error())
	}
	return fileKey, count, ownerStr, nil
}

// Given filekey, content, and the node#, create a ContentChunk in Datastore and return its random UUID
func CreateContentChunk(fileKey []byte, content []byte, counter int) (contentUUID uuid.UUID, err error) {
	var tempKey []byte
	chunkUUID := uuid.New()
	chunk := ContentChunk{content}

	// Generate tag key
	tagKey, err := userlib.HashKDF(fileKey, []byte("Content"+strconv.Itoa(counter)))
	if err != nil {
		return NilUUID(), errors.New("Unable to generate HMAC key for contents: " + err.Error())
	}

	tempKey, err = userlib.HashKDF(fileKey, []byte("EncryptFile"))
	if err != nil {
		return NilUUID(), errors.New("Unable to generate content encryption key: " + err.Error())
	}

	err = WrapStruct(chunk, chunkUUID, "HMAC", tagKey, "Symmetric", tempKey)
	if err != nil {
		return NilUUID(), errors.New("Failed to wrap contents: " + err.Error())
	}

	return chunkUUID, nil
}

func IsAuthStruct(currHeader HeaderFile, fileKey []byte) (isShared bool, headerFilePtr *HeaderFile, err error) {
	if !userlib.HMACEqual([]byte(currHeader.ToHeader.String()), []byte(NilUUID().String())) {
		var ownerHeader HeaderFile

		tagKey, err := userlib.HashKDF(fileKey, []byte("header"))
		if err != nil {
			return false, nil, errors.New("Unable to generate HMAC key for owner's header file: " + err.Error())
		}

		err = UnwrapStruct(currHeader.ToHeader, &ownerHeader, "HMAC", tagKey, "None", "")
		if err != nil {
			return false, nil, errors.New("Unable to unwrap owner's header file: " + err.Error())
		}

		return true, &ownerHeader, nil
	}

	return false, &currHeader, nil
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	// var userdata User
	var tempKey []byte

	// Check that the username is not empty
	if len(username) == 0 {
		return nil, errors.New("username is empty")
	}

	// Check that the user does not exist yet
	_, exists := userlib.KeystoreGet(username)
	if exists {
		return nil, errors.New("User already exists")
	}

	// Generate the RSA & signature public/private key pairs
	var publicKey userlib.PKEEncKey
	var privateKey userlib.PKEDecKey
	publicKey, privateKey, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, errors.New("Failed to generate RSA keys: " + err.Error())
	}

	var signKey userlib.DSSignKey
	var verifyKey userlib.DSVerifyKey
	signKey, verifyKey, err = userlib.DSKeyGen()
	if err != nil {
		return nil, errors.New("Failed to generate signature keys: " + err.Error())
	}

	// Add public keys to Keystore
	err = userlib.KeystoreSet(username, publicKey)
	if err != nil {
		return nil, errors.New("Failed to set new public key: " + err.Error())
	}
	err = userlib.KeystoreSet(username+"VerifyKey", verifyKey)
	if err != nil {
		return nil, errors.New("Failed to set new verify key: " + err.Error())
	}

	// Make a source key
	sourceKey := userlib.Argon2Key([]byte(password), []byte(username), 16)

	// Generate PasswordHash
	salt := userlib.RandomBytes(16)
	passwordHash := userlib.Argon2Key([]byte(password), salt, 16)

	// Store values in struct
	userdata := User{username, passwordHash, salt, privateKey, signKey, sourceKey}

	// Store values in a wrapper at UUID(H(username))
	var userHashUUID uuid.UUID
	userHashUUID, err = uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, errors.New("Failed to create UUID from username hash: " + err.Error())
	}

	tempKey, err = userlib.HashKDF(sourceKey, []byte("UserDataEncryption"))
	if err != nil {
		return nil, errors.New("Failed to generate new hash key for encryption Key: " + err.Error())
	}

	err = WrapStruct(userdata, userHashUUID, "Signature", signKey, "Symmetric", tempKey)
	if err != nil {
		return nil, errors.New("Failed to create wrapper struct: " + err.Error())
	}

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	// Check that the user exists
	_, exists := userlib.KeystoreGet(username)
	if !exists {
		return nil, errors.New("User has not been created")
	}

	// Fetch from datastore at UUID(H(username))
	var userHashUUID uuid.UUID
	userHashUUID, err = uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, errors.New("Failed to create UUID from username hash: " + err.Error())
	}

	// Fetch the verify key for the user
	verifyKey, exists := userlib.KeystoreGet(username + "VerifyKey")
	if !exists {
		return nil, errors.New("failed to retrieve verifyKey")
	}

	// Generate a sourcekey using the provided credentials
	sourceKey := userlib.Argon2Key([]byte(password), []byte(username), 16)

	// Fetch & decrypt the user struct
	var tempKey []byte
	tempKey, err = userlib.HashKDF(sourceKey, []byte("UserDataEncryption"))
	if err != nil {
		return nil, errors.New("Failed to generate new hash key for encryption key: " + err.Error())
	}

	err = UnwrapStruct(userHashUUID, &userdata, "Signature", verifyKey, "Symmetric", tempKey)
	if err != nil {
		return nil, errors.New("Failed to retrieve the user struct: " + err.Error())
	}

	// Check credentials
	passwordHash := userlib.Argon2Key([]byte(password), userdata.Salt, 16)
	if !userlib.HMACEqual(passwordHash, userdata.PasswordHash) {
		return nil, errors.New("Invalid Credentials: " + err.Error())
	}

	// Repopulate the sourceKey field
	userdata.sourceKey = sourceKey
	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	var tempKey []byte

	//// ContentChunk
	// Encrypt the contents
	fileKey := userlib.RandomBytes(16)

	chunkUUID, err := CreateContentChunk(fileKey, content, 0)
	if err != nil {
		return errors.New("Error creating content chunk: " + err.Error())
	}

	//// Create and store a FileNode
	node := FileNode{NilUUID(), chunkUUID}

	// Create tag key
	tempKey, err = userlib.HashKDF(fileKey, []byte("Node0"))
	if err != nil {
		return errors.New("Unable to generate HMAC key for node: " + err.Error())
	}

	// Wrap and store struct
	nodeUUID := uuid.New()
	err = WrapStruct(node, nodeUUID, "HMAC", tempKey, "Symmetric", fileKey)
	if err != nil {
		return errors.New("Unable to wrap FileNode: " + err.Error())
	}

	// Wrap the header file
	headerFileUUID := uuid.New()
	headerFile := HeaderFile{nodeUUID, nodeUUID, NilUUID(), nil, nil, nil, NilUUID()}
	err = WrapHeaderFile(headerFileUUID, headerFile, "HMAC", nil, fileKey, userdata.Username, userdata.Username, 1)
	if err != nil {
		return errors.New("Failed to create header file wrapper: " + err.Error())
	}

	//// NameFile
	var nameFileUUID uuid.UUID

	// UUID(H(H(filename) || username))
	nameFileUUID, err = NameFileUUID(filename, userdata.Username)
	if err != nil {
		return errors.New("Unable to create name file UUID: " + err.Error())
	}
	nameFile := NameFile{headerFileUUID}

	// Create tag key
	tagKey, err := userlib.HashKDF(userdata.sourceKey, []byte(filename))
	if err != nil {
		return errors.New("Unable to generate HMAC key for nameFile: " + err.Error())
	}

	err = WrapStruct(nameFile, nameFileUUID, "HMAC", tagKey, "None", "")
	if err != nil {
		return errors.New("Unable to wrap nameFile: " + err.Error())
	}
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// get name file
	nameFileUUID, err := NameFileUUID(filename, userdata.Username)
	if err != nil {
		return errors.New("Unable to locate name file: " + err.Error())
	}

	tagKey, err := userlib.HashKDF(userdata.sourceKey, []byte(filename))
	if err != nil {
		return errors.New("Unable to generate HMAC key for nameFile: " + err.Error())
	}

	var nameFile NameFile
	err = UnwrapStruct(nameFileUUID, &nameFile, "HMAC", tagKey, "None", "")
	if err != nil {
		return errors.New("Unable to unwrap nameFile: " + err.Error())
	}

	// get headerFile file
	var headerFile HeaderFile
	headerFileUUID := nameFile.HeaderPtr
	fileKey, count, owner, err := UnwrapHeaderFile(nameFile.HeaderPtr, &headerFile, "HMAC", nil, true, []byte{}, userdata.DecKey)
	if err != nil {
		return errors.New("Failed to unwrap the header file: " + err.Error())
	}

	// check if this header is an auth struct. if it is, locate the real header file.
	isShared, headerPtr, err := IsAuthStruct(headerFile, fileKey)
	if err != nil {
		return errors.New("Error while checking auth/header status: " + err.Error())
	}

	if isShared {
		headerFileUUID = headerFile.ToHeader
		headerFile = *headerPtr

		_, count, owner, err = UnwrapHeaderFile(headerFileUUID, &headerFile, "HMAC", nil, false, fileKey, userdata.DecKey)
		if err != nil {
			return errors.New("Failed to unwrap the header file: " + err.Error())
		}
	}

	// Create a new content chunk
	var contentUUID uuid.UUID
	contentUUID, err = CreateContentChunk(fileKey, content, count)
	if err != nil {
		return errors.New("Error creating content chunk: " + err.Error())
	}

	//// Create and store a new FileNode
	node := FileNode{NilUUID(), contentUUID}

	// Create tag key
	tempKey, err := userlib.HashKDF(fileKey, []byte("Node"+strconv.Itoa(count)))
	if err != nil {
		return errors.New("Unable to generate HMAC key for node: " + err.Error())
	}

	// Wrap and store struct
	nodeUUID := uuid.New()
	err = WrapStruct(node, nodeUUID, "HMAC", tempKey, "Symmetric", fileKey)
	if err != nil {
		return errors.New("Unable to wrap FileNode: " + err.Error())
	}

	// Get current final node
	var currFinalNode FileNode
	tagKey, err = userlib.HashKDF(fileKey, []byte("Node"+strconv.Itoa(count-1)))
	if err != nil {
		return errors.New("Unable to generate node tag key: " + err.Error())
	}

	// Update the current final node
	UnwrapStruct(headerFile.FinalNode, &currFinalNode, "HMAC", tagKey, "Symmetric", fileKey)
	currFinalNode.NextNode = nodeUUID
	WrapStruct(currFinalNode, headerFile.FinalNode, "HMAC", tagKey, "Symmetric", fileKey)

	// Update the header file
	updatedHeader := HeaderFile{headerFile.InitialNode, nodeUUID, headerFile.ShareNode, nil, nil, nil, NilUUID()}
	err = WrapHeaderFile(headerFileUUID, updatedHeader, "HMAC", nil, fileKey, owner, owner, count+1)
	if err != nil {
		return errors.New("Failed to update the header file: " + err.Error())
	}

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	var tempKey []byte

	// Get the namefile
	var nameFileUUID uuid.UUID
	var nameFile NameFile
	nameFileUUID, err = NameFileUUID(filename, userdata.Username)
	if err != nil {
		return nil, errors.New("Failed to run uuid.FromBytes: " + err.Error())
	}

	// create tagkey
	tagKey, err := userlib.HashKDF(userdata.sourceKey, []byte(filename))
	if err != nil {
		return nil, errors.New("Unable to generate HMAC key for nameFile: " + err.Error())
	}

	err = UnwrapStruct(nameFileUUID, &nameFile, "HMAC", tagKey, "None", "")
	if err != nil {
		return nil, errors.New("Failed to unwrap the name file: " + err.Error())
	}

	// Get the headerfile
	var header HeaderFile
	fileKey, maxCount, _, err := UnwrapHeaderFile(nameFile.HeaderPtr, &header, "HMAC", nil, true, []byte{}, userdata.DecKey)
	if err != nil {
		return nil, errors.New("Failed to unwrap the header file: " + err.Error())
	}

	// check if this header is an auth struct. if it is, locate the real header file.
	isShared, headerPtr, err := IsAuthStruct(header, fileKey)
	if err != nil {
		return nil, errors.New("Error while checking auth/header status: " + err.Error())
	}

	if isShared {
		headerFileUUID := header.ToHeader
		header = *headerPtr

		_, maxCount, _, err = UnwrapHeaderFile(headerFileUUID, &header, "HMAC", nil, false, fileKey, userdata.DecKey)
		if err != nil {
			return nil, errors.New("Failed to unwrap the header file: " + err.Error())
		}
	}

	// traverse the link list
	var curr FileNode
	var currUUID uuid.UUID
	var currContent ContentChunk
	count := 0
	for currUUID = header.InitialNode; count < maxCount; currUUID = curr.NextNode {
		// For each node, unwrap the struct, decrypt the node
		tagKey, err := userlib.HashKDF(fileKey, []byte("Node"+strconv.Itoa(count)))
		if err != nil {
			return nil, errors.New("Unable to generate content key: " + err.Error())
		}

		err = UnwrapStruct(currUUID, &curr, "HMAC", tagKey, "Symmetric", fileKey)
		if err != nil {
			return nil, errors.New("Unable to unwrap FileNode: " + err.Error())
		}

		// get the content chunk, unwrap the struct, decrypt it
		tagKey, err = userlib.HashKDF(fileKey, []byte("Content"+strconv.Itoa(count)))
		if err != nil {
			return nil, errors.New("Unable to generate content key: " + err.Error())
		}

		tempKey, err = userlib.HashKDF(fileKey, []byte("EncryptFile"))
		if err != nil {
			return nil, errors.New("Unable to generate content encryption key: " + err.Error())
		}

		err = UnwrapStruct(curr.Content, &currContent, "HMAC", tagKey, "Symmetric", tempKey)
		if err != nil {
			return nil, errors.New("Error unwrapping content chunk: " + err.Error())
		}

		content = append(content, currContent.Content...)

		count = count + 1
	}

	return content, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	// Get the namefile
	var nameFileUUID uuid.UUID
	var nameFile NameFile
	nameFileUUID, err = NameFileUUID(filename, userdata.Username)
	if err != nil {
		return NilUUID(), errors.New("Failed to run uuid.FromBytes: " + err.Error())
	}

	// create tagkey
	tagKey, err := userlib.HashKDF(userdata.sourceKey, []byte(filename))
	if err != nil {
		return NilUUID(), errors.New("Unable to generate HMAC key for nameFile: " + err.Error())
	}

	err = UnwrapStruct(nameFileUUID, &nameFile, "HMAC", tagKey, "None", "")
	if err != nil {
		return NilUUID(), errors.New("Failed to unwrap the name file: " + err.Error())
	}

	// Get the headerfile
	var header HeaderFile
	fileKey, count, owner, err := UnwrapHeaderFile(nameFile.HeaderPtr, &header, "HMAC", nil, true, []byte{}, userdata.DecKey)
	if err != nil {
		return NilUUID(), errors.New("Failed to unwrap the header file: " + err.Error())
	}

	// Auth struct either points to this headerfile or the owner's headerfile
	isShared, _, err := IsAuthStruct(header, fileKey)
	if err != nil {
		return NilUUID(), errors.New("Error while checking auth/header status: " + err.Error())
	}
	var toHeader uuid.UUID
	if isShared { // Go to header
		toHeader = header.ToHeader
	} else { // Owner's header is just pointer from nameFile
		toHeader = nameFile.HeaderPtr
	}

	// Create an auth struct for the shared user
	authUUID := uuid.New()
	authStruct := HeaderFile{NilUUID(), NilUUID(), NilUUID(), nil, nil, nil, toHeader}
	err = WrapHeaderFile(authUUID, authStruct, "Signature", userdata.SignKey, fileKey, recipientUsername, owner, -1)

	if err != nil {
		return NilUUID(), errors.New("failed to create recipient auth struct")
	}

	//// ShareNode
	// Get caller's ShareNode address from their headerfile
	// and instantiate a new one if it's nil
	shareNodeUUID := header.ShareNode
	var shareMap map[string]uuid.UUID
	var shareNode ShareNode
	var encKey []byte

	encKey, err = userlib.HashKDF(fileKey, []byte("EncryptShareNode"))
	if err != nil {
		return NilUUID(), errors.New("Unable to generate encKey for ShareNode: " + err.Error())
	}

	tagKey, err = userlib.HashKDF(fileKey, []byte("ShareNode"))
	if err != nil {
		return NilUUID(), errors.New("Unable to generate tagKey for ShareNode: " + err.Error())
	}

	if userlib.HMACEqual([]byte(shareNodeUUID.String()), []byte(NilUUID().String())) {
		// Instantiate a new ShareNode
		shareNodeUUID = uuid.New()
		// Make a map for it and place the recipient user in it
		shareMap = make(map[string]uuid.UUID)
		shareNode = ShareNode{shareMap}

		err = WrapStruct(shareNode, shareNodeUUID, "HMAC", tagKey, "Symmetric", encKey)
		if err != nil {
			return NilUUID(), errors.New("Failed to create share node file wrapper: " + err.Error())
		}

		// update your header file
		header.ShareNode = shareNodeUUID
		err = WrapHeaderFile(nameFile.HeaderPtr, header, "HMAC", nil, fileKey, userdata.Username, owner, count)
		if err != nil {
			return NilUUID(), errors.New("Error updating header file: " + err.Error())
		}
	}
	// Update the ShareNode by unwrapping it, updating the map, and rewrapping it
	err = UnwrapStruct(shareNodeUUID, &shareNode, "HMAC", tagKey, "Symmetric", encKey)
	if err != nil {
		return NilUUID(), errors.New("Failed to unwrap ShareNode: " + err.Error())
	}

	shareNode.SharedMap[recipientUsername] = authUUID
	err = WrapStruct(shareNode, shareNodeUUID, "HMAC", tagKey, "Symmetric", encKey)
	if err != nil {
		return NilUUID(), errors.New("Failed to rewrap ShareNode: " + err.Error())
	}

	return authUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// validate the invite
	verifyKey, ok := userlib.KeystoreGet(senderUsername + "VerifyKey")
	if !ok {
		return errors.New("Failed to retrieve verifyKey for sender " + senderUsername)
	}

	var authStruct HeaderFile
	fileKey, count, owner, err := UnwrapHeaderFile(invitationPtr, &authStruct, "Signature", verifyKey, true, []byte{}, userdata.DecKey)
	if err != nil {
		return errors.New("Invalid invite: " + err.Error())
	}

	var ownerHeader HeaderFile
	_, _, _, err = UnwrapHeaderFile(authStruct.ToHeader, &ownerHeader, "HMAC", nil, false, fileKey, userdata.DecKey)
	if err != nil {
		return errors.New("Invalid invite: " + err.Error())
	}

	// now we rewrap the auth struct with an hmac instead of a signature
	err = WrapHeaderFile(invitationPtr, authStruct, "HMAC", nil, fileKey, userdata.Username, owner, count)
	if err != nil {
		return errors.New("Error rewrapping validated auth struct file: " + err.Error())
	}

	//// create NameFile at UUID(H(H(filename) || username))
	nameFileUUID, err := NameFileUUID(filename, userdata.Username)
	if err != nil {
		return errors.New("Unable to create name file UUID: " + err.Error())
	}
	nameFile := NameFile{invitationPtr}

	// Create tag key
	tagKey, err := userlib.HashKDF(userdata.sourceKey, []byte(filename))
	if err != nil {
		return errors.New("Unable to generate HMAC key for nameFile: " + err.Error())
	}

	err = WrapStruct(nameFile, nameFileUUID, "HMAC", tagKey, "None", "")
	return err
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	//// Initial goal: get nameFile -> headerFile -> shareNode
	// Get the namefile
	var nameFileUUID uuid.UUID
	var nameFile NameFile
	var err error
	nameFileUUID, err = NameFileUUID(filename, userdata.Username)
	if err != nil {
		return errors.New("Failed to run uuid.FromBytes: " + err.Error())
	}

	// create tagkey for nameFile
	tagKey, err := userlib.HashKDF(userdata.sourceKey, []byte(filename))
	if err != nil {
		return errors.New("Unable to generate HMAC key for nameFile: " + err.Error())
	}

	err = UnwrapStruct(nameFileUUID, &nameFile, "HMAC", tagKey, "None", "")
	if err != nil {
		return errors.New("Failed to unwrap the name file: " + err.Error())
	}

	// Get the headerfile
	oldOwnerHeaderUUID := nameFile.HeaderPtr
	var header HeaderFile
	fileKey, oldCounter, _, err := UnwrapHeaderFile(oldOwnerHeaderUUID, &header, "HMAC", nil, true, []byte{}, userdata.DecKey)
	if err != nil {
		return errors.New("Failed to unwrap the header file: " + err.Error())
	}

	// Get and update the sharenode
	shareNodeUUID := header.ShareNode
	var shareNode ShareNode

	encKey, err := userlib.HashKDF(fileKey, []byte("EncryptShareNode"))
	if err != nil {
		return errors.New("Unable to generate encKey for ShareNode: " + err.Error())
	}

	tagKey, err = userlib.HashKDF(fileKey, []byte("ShareNode"))
	if err != nil {
		return errors.New("Unable to generate tagKey for ShareNode: " + err.Error())
	}

	err = UnwrapStruct(shareNodeUUID, &shareNode, "HMAC", tagKey, "Symmetric", encKey)
	if err != nil {
		return errors.New("Failed to unwrap owner ShareNode: " + err.Error())
	}
	delete(shareNode.SharedMap, recipientUsername) // Remove recipient user from shared map
	// ShareNode is not done getting updated so it will be rewrapped later in this function

	// Read the file and store to new location with new nameFile, headerFile, fileNodes, and contentChunks
	// NOTE: nameFile stays at same location but the rest of the objects are at random UUID's
	var content []byte
	content, err = userdata.LoadFile(filename)
	if err != nil {
		return errors.New("Failed to load file: " + err.Error())
	}

	err = userdata.StoreFile(filename, content)
	if err != nil {
		return errors.New("Failed to store file: " + err.Error())
	}

	// -------------------------------- Part two of this function --------------------------------
	//// Goal: point new HeaderFile to old ShareNode (encrypted with new fileKey)
	//// and recursively update recipient's headerFiles and shareNodes in ShareMap
	//// to point to new headerFile, store new fileKey, and encrypt with new fileKey
	nameFileUUID, err = NameFileUUID(filename, userdata.Username)
	if err != nil {
		return errors.New("Failed to run uuid.FromBytes: " + err.Error())
	}

	// create tagkey for nameFile
	tagKey, err = userlib.HashKDF(userdata.sourceKey, []byte(filename))
	if err != nil {
		return errors.New("Unable to generate HMAC key for nameFile: " + err.Error())
	}

	err = UnwrapStruct(nameFileUUID, &nameFile, "HMAC", tagKey, "None", "")
	if err != nil {
		return errors.New("Failed to unwrap the name file: " + err.Error())
	}

	// Get the new headerfile with new fileKey
	var newHeader HeaderFile
	var counter int
	var newFileKey []byte
	var newEncKey []byte
	newFileKey, counter, _, err = UnwrapHeaderFile(nameFile.HeaderPtr, &newHeader, "HMAC", nil, true, []byte{}, userdata.DecKey)
	if err != nil {
		return errors.New("Failed to unwrap the header file: " + err.Error())
	}

	// Get new encKey
	newEncKey, err = userlib.HashKDF(newFileKey, []byte("EncryptShareNode"))
	if err != nil {
		return errors.New("Unable to generate encKey for ShareNode: " + err.Error())
	}

	newTagKey, err := userlib.HashKDF(fileKey, []byte("ShareNode"))
	if err != nil {
		return errors.New("Unable to generate tagKey for ShareNode: " + err.Error())
	}

	// Recursively Update the recipient headerFiles and shareNodes
	err = UpdateSharedMap(shareNode.SharedMap, fileKey, newFileKey, newTagKey, newEncKey, nameFile.HeaderPtr)
	if err != nil {
		return errors.New("Failed to update shared map: " + err.Error())
	}

	// Wrap shareNode with new encKey
	err = WrapStruct(shareNode, shareNodeUUID, "Signature", userdata.SignKey, "Symmetric", newEncKey)
	if err != nil {
		return errors.New("Failed to rewrap ShareNode: " + err.Error())
	}

	// Update and wrap new headerFile
	newHeader.ShareNode = shareNodeUUID
	err = WrapHeaderFile(nameFile.HeaderPtr, newHeader, "HMAC", nil, newFileKey, userdata.Username, userdata.Username, counter)
	if err != nil {
		return errors.New("Failed to wrap new headerFile: " + err.Error())
	}

	// Delete old file in Datastore
	// -- at minimum delete the owner's header file, so no recipients can call Load or Append
	// TODO delete the rest of the old file, so that they can't call datastore get with recorded addresses to get the old file
	prev := oldOwnerHeaderUUID
	var curr FileNode
	var currUUID uuid.UUID
	count := 0

	// Delete the FileNodes and the ContentChunks
	for currUUID = header.InitialNode; count < oldCounter; currUUID = curr.NextNode {
		tagKey, err = userlib.HashKDF(fileKey, []byte("Node"+strconv.Itoa(count)))
		if err != nil {
			return errors.New("Unable to generate HMAC key for node: " + err.Error())
		}

		err = UnwrapStruct(currUUID, &curr, "HMAC", tagKey, "Symmetric", fileKey)
		if err != nil {
			return errors.New("Unable to unwrap file node for deletion: " + err.Error())
		}

		count = count + 1
		userlib.DatastoreDelete(prev)
		userlib.DatastoreDelete(curr.Content)
	}
	userlib.DatastoreDelete(currUUID)
	return nil
}

// Given a shareMap, a new file key, and the owner's new header UUID,
// Recursively access the recipients in their shareNode, update their headerFiles
// to point to the new owner's headerFile and store the new fileKey
// and recursively update headerFiles in ShareMap to point to new headerFile and store new fileKey
func UpdateSharedMap(shareMap map[string]uuid.UUID, oldFileKey []byte, fileKey []byte, tagKey []byte, encKey []byte, ownerHeaderUUID uuid.UUID) (err error) {
	var recipientHeader HeaderFile
	var recShareNode ShareNode
	var garbageKey userlib.PrivateKeyType // Create unused garbage key for unwrap headerfile
	_, garbageKey, err = userlib.PKEKeyGen()
	if err != nil {
		return errors.New("Failed to generate garbage key: " + err.Error())
	}

	for name, headerUUID := range shareMap {
		// Unwrap recipient header but don't get the fileKey from it bc we want to use the new one
		_, counter, owner, err := UnwrapHeaderFile(headerUUID, &recipientHeader, "HMAC", nil, false, oldFileKey, garbageKey)
		if err != nil {
			return errors.New("Failed to unwrap the header file: " + err.Error())
		}

		// Update recipient header and rewrap it
		recipientHeader.ToHeader = ownerHeaderUUID
		err = WrapHeaderFile(headerUUID, recipientHeader, "HMAC", nil, fileKey, name, owner, counter)
		if err != nil {
			return errors.New("Failed to rewrap the header file: " + err.Error())
		}

		// Access recipients share node, call UpdateSharedMap on it, and rewrap the shareNode
		if !userlib.HMACEqual([]byte(recipientHeader.ShareNode.String()), []byte(NilUUID().String())) {
			err = UnwrapStruct(recipientHeader.ShareNode, &recShareNode, "HMAC", tagKey, "Symmetric", encKey)
			if err != nil {
				return errors.New("Failed to unwrap ShareNode: " + err.Error())
			}
			err = UpdateSharedMap(recShareNode.SharedMap, oldFileKey, fileKey, tagKey, encKey, ownerHeaderUUID)
			if err != nil {
				return errors.New("Failed to recursively update shared map: " + err.Error())
			}
			err = WrapStruct(recShareNode, recipientHeader.ShareNode, "HMAC", tagKey, "Symmetric", encKey)
			if err != nil {
				return errors.New("Failed to rewrap recipient's ShareNode: " + err.Error())
			}
		}
	}
	return err
}

// TODO: in append to file and load file you should check if they are in the sharedmap to add extra security
// Stores important metadata about a file.
// Security:
//   - fileKey is encrypted with public key
//   - owner is encrypted with fileKey + "OwnerUsername"
//   - counter is encrypted with fileKey + {counter}
//
// HMACed with fileKey + "header"
// type HeaderFile struct {
// 	InitialNode      uuid.UUID
// 	FinalNode        uuid.UUID
// 	ShareNode        uuid.UUID
// 	EncryptedOwner   []byte
// 	EncryptedFileKey []byte
// 	EncryptedCounter []byte    // how many nodes are in the file
// 	ToHeader         uuid.UUID // points to a header if this is an auth struct, NilUUID if not
// }

// // Sharing metadata, encrypted with file key, and signed by whoever the share node belongs to
// // Security: encrypted with fileKey + purpose "EncryptShareNode".
// HMACed with filekey + purpose "HMACShareNode."
// type ShareNode struct {
// 	SharedMap map[string]uuid.UUID // Users we shared this with (username: headerfile uuid)
// }
