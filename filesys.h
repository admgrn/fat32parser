#ifndef _FILESYS_H
#define _FILESYS_H

#include <string>
#include <list>
#include <vector>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <exception>
#include <map>
#include <functional>

class Filesys
{
  public:
    Filesys(std::string);
    bool CallFunct(std::string&, std::vector<std::string>&);
    bool HasError();
    void Validate();
    std::string GetLocation();
    ~Filesys();

  private:
    uint8_t* mFilesys_;
    size_t filesys_size_;
    std::string fname_;
    int fd_;
    bool error_;
    std::map<std::string, 
         std::function<void (Filesys&, 
         std::vector<std::string>&)>>
        functions_;

    enum AttrMask
    {
      RDONLY = 1 << 0,
      HIDDEN = 1 << 1,
      SYS = 1 << 2,
      VOLID = 1 << 3,
      DIRECT = 1 << 4,
      ARCHIVE = 1 << 5,
      LONG = RDONLY | HIDDEN | SYS | VOLID
    };

    enum OpenMask
    {
      READ = 1 << 0,
      WRITE = 1 << 1
    };

    struct Fat32Info
    {
        uint8_t Signature[2];
        uint16_t BytesPerSec;
        uint16_t RootEntCnt;
        uint32_t RootDirSector;
        uint32_t FATSz16;
        uint32_t FATSz32;
        uint32_t FATSz;
        uint32_t RsvdSecCnt;
        uint32_t NumFats;
        uint32_t SecPerClus;
        uint32_t FirstDataSec;
        uint32_t RootClus;
        uint32_t FsInfo;
        uint32_t TotSec;
        uint32_t SecPerFat;

        uint32_t GetFirstSectorOfClus(uint32_t);
        uint32_t GetThisFatSecN(uint32_t);
        uint32_t GetThisFatEntOff(uint32_t);
        uint32_t GetEndOfFat();
    };

    class FileEntry
    {
      public:
        std::string name;
        uint8_t attr;
        uint16_t lo;
        uint16_t hi;
        uint16_t wrtTime;
        uint16_t wrtDate;
        uint32_t size;
        uint32_t clus;
        uint32_t entryLoc;
        uint32_t openInfo;

        FileEntry(char*, uint8_t, uint16_t, uint16_t, uint32_t, uint32_t);

        FileEntry(const FileEntry&);
        std::string GetShortName();
        void SetClus(uint32_t);
        bool IsDir();
        void SetCurrentTime();
    };

    uint32_t cwd_;
    std::string location_;
    struct Fat32Info finfo_;
    std::list<FileEntry> openTable_;

    void UpdateClusCount(std::function 
                      <uint32_t (uint32_t)> op);
    uint32_t GetFATNxtFree();
    void SetFATNxtFree(uint32_t);
    uint32_t GetNFreeClus();
    void SetNFreeClus(uint32_t);
    template <typename T>
    void WriteValue(T*, size_t, size_t, size_t);
    template <typename T>
    void ReadValue(T*, size_t, size_t, size_t);
    uint32_t GetNextClus(uint32_t);
    void SetNextClus(uint32_t, uint32_t);
    uint32_t AllocateCluster(uint32_t = 0);
    void DeallocateChain(uint32_t);
    void ZeroOutCluster(uint32_t);
    std::string ValidateFileName(std::string);
    std::list<FileEntry>* GetFileList(uint32_t, 
                                      bool = false);
    std::list<std::string> ParseAddress(std::string);
    uint32_t NavToDir(std::list<std::string>&, size_t,
                      size_t);
    std::string GenPathName(uint32_t);
    void SaveFileEntry(FileEntry&);
    FileEntry* AddEntry(uint32_t, std::string, uint8_t);
    uint32_t FileOperate(char*, uint32_t, uint32_t, FileEntry&, 
         std::function<void (Filesys&, char*, size_t, 
         size_t, size_t)> funct);

    void Fsinfo(std::vector<std::string>&);
    void Ls(std::vector<std::string>&);
    void Mkdir(std::vector<std::string>&);
    void Create(std::vector<std::string>&);
    void Cd(std::vector<std::string>&);
    void Size(std::vector<std::string>&);
    void Open(std::vector<std::string>&);
    void Close(std::vector<std::string>&);
    void Read(std::vector<std::string>&);
    void Write(std::vector<std::string>&);
    void Rm(std::vector<std::string>&);
    void Rmdir(std::vector<std::string>&);
    void Undelete(std::vector<std::string>&);
    void Help(std::vector<std::string>&);
};
#endif
