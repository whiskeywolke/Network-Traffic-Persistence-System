//
// Created by ubuntu on 08.06.21.
//

#ifndef IMPLEMENTATION_DIRECTORY_H
#define IMPLEMENTATION_DIRECTORY_H

#include <dirent.h>
#include <sys/stat.h>


namespace common{
    uint64_t getTotalFilesSize(const char *path) { //works only in linux
        struct dirent *entry;
        DIR *dir = opendir(path);

        if (dir == nullptr) {
            std::cout << "dir is null" << std::endl;
            return {};
        }
        uint64_t filesizeBytes = 0;
        while ((entry = readdir(dir)) != nullptr) {
            std::string filename = entry->d_name;
            if (filename.length() == 37 && filename.substr(33, 36) == ".bin" && filename.at(16) == '-') {
                struct stat st;
                if (stat((path + filename).c_str(), &st) == 0)
                    filesizeBytes += st.st_size;
                else {
                    closedir(dir);
                    exit(1);
                }
            }
        }
        closedir(dir);
        return filesizeBytes;
    }

    std::vector<std::string> getFilesFromDir(const char *path) {
        struct dirent *entry;
        DIR *dir = opendir(path);

        if (dir == nullptr) {
            std::cout << "dir is null" << std::endl;
            return {};
        }
        std::vector<std::string> files{};
        while ((entry = readdir(dir)) != nullptr) {
            std::string filename = entry->d_name;
            if (filename.length() == 37 && filename.substr(33, 36) == ".bin" && filename.at(16) == '-') {
                files.push_back(filename);
            }
        }
        closedir(dir);
        return files;
    }
}

#endif //IMPLEMENTATION_DIRECTORY_H
