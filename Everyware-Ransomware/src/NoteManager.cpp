#include "../include/NoteManager.h"
#include <fstream>
#include <iostream>
#include <filesystem>

std::string NoteManager::buildNoteText(const std::string& target, const std::string& hint) const {
    std::string note;
    note += "=== FILES ENCRYPTED (SIMULATION) ===\n\n";
    note += "This is a simulation note created by EncryptSim (educational use only).\n";
    note += "Affected path: " + target + "\n\n";
    note += "To restore the original file, run the tool in 'decrypt' mode with the generated .enc file.\n\n";
    if (!hint.empty()) {
        note += "Hint: " + hint + "\n\n";
    }
    note += "NOTE: This is for testing only. Do not run on important files.\n";
    note += "======================================\n";
    return note;
}

bool NoteManager::createNoteOverwrite(const std::string& targetPath, const std::string& hint) const {
    std::ofstream out(targetPath, std::ios::binary | std::ios::trunc);
    if (!out) { std::cerr << "[NoteManager] failed to open for overwrite: " << targetPath << "\n"; return false; }
    std::string note = buildNoteText(targetPath, hint);
    out.write(note.data(), static_cast<std::streamsize>(note.size()));
    out.close();
    std::cout << "[NoteManager] Overwrote: " << targetPath << "\n";
    return true;
}

bool NoteManager::createNoteNextToEncrypted(const std::string& encryptedPath, const std::string& hint) const {
    try {
        std::filesystem::path p(encryptedPath);
        std::filesystem::path dir = p.parent_path();
        std::filesystem::path notePath = dir / "README_FOR_DECRYPTION.txt";
        std::ofstream out(notePath, std::ios::binary | std::ios::trunc);
        if (!out) { std::cerr << "[NoteManager] failed to create note: " << notePath << "\n"; return false; }
        std::string note = buildNoteText(encryptedPath, hint);
        out.write(note.data(), static_cast<std::streamsize>(note.size()));
        out.close();
        std::cout << "[NoteManager] Created note: " << notePath << "\n";
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[NoteManager] exception: " << e.what() << "\n";
        return false;
    }
}