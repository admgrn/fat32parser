#include <filesys.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <initializer_list>
#include <cctype>
#include <cstring>
#include <cmath>
#include <ctime>
#include <algorithm>
#include <sstream>

// Sets mask to take lower 28 bits
#define FATMASK 0x0FFFFFFF
// Values of this and higher indicate EoC
#define FATEND 0x0FFFFFF8
// File is not Allocated
#define DEALLOC 0xe5

Filesys::Filesys(std::string fname) : mFilesys_(0), 
                                      filesys_size_(0),
                                      fname_(fname),
                                      fd_(0),
                                      error_(false), 
                                      functions_(),
                                      cwd_(),
                                      finfo_(),
                                      openTable_()
{
  struct stat fstatus;

  // Open File Descriptor
  fd_ = open(fname_.c_str(), O_RDWR);

  if (fd_ < 0)
  {
    error_ = true;
    return;
  }

  // Get File Stats
  if (fstat(fd_, &fstatus) < 0)
  {
    error_ = true;
    return;
  }

  // Map file to array -> mFilesys_
  filesys_size_ = fstatus.st_size;
  mFilesys_ = (uint8_t*)mmap(0, filesys_size_, PROT_READ |
      PROT_WRITE | PROT_EXEC, MAP_SHARED, fd_, 0);

  // Register functions here
  functions_.insert(std::make_pair("fsinfo", &Filesys::Fsinfo));
  functions_.insert(std::make_pair("ls", &Filesys::Ls));
  functions_.insert(std::make_pair("cd", &Filesys::Cd));
  functions_.insert(std::make_pair("size", &Filesys::Size));
  functions_.insert(std::make_pair("open", &Filesys::Open));
  functions_.insert(std::make_pair("close", &Filesys::Close));
  functions_.insert(std::make_pair("read", &Filesys::Read));
  functions_.insert(std::make_pair("write", &Filesys::Write));
  functions_.insert(std::make_pair("mkdir", &Filesys::Mkdir));
  functions_.insert(std::make_pair("rm", &Filesys::Rm));
  functions_.insert(std::make_pair("rmdir", &Filesys::Rmdir));
  functions_.insert(std::make_pair("create", &Filesys::Create));
  functions_.insert(std::make_pair("undelete", &Filesys::Undelete));
  functions_.insert(std::make_pair("help", &Filesys::Help));
}

// Close file descriptor and unmaps files ystem
Filesys::~Filesys()
{
  munmap(mFilesys_, filesys_size_);
  if (fd_ >= 0)
    close(fd_);
}

// Retreives and Validates information from the file system
void Filesys::Validate()
{
  if (error_)
    throw  std::exception();

  ReadValue(finfo_.Signature, 2, 510, 1);

  if (finfo_.Signature[0] != 0x55 || finfo_.Signature[1] != 0xaa)
    throw std::exception();

  ReadValue(&(finfo_.BytesPerSec), 1, 11, 2); 
  ReadValue(&(finfo_.RootEntCnt), 1, 17, 2);
  ReadValue(&(finfo_.FATSz16), 1, 22, 2);
  ReadValue(&(finfo_.FATSz32), 1, 36, 4);
  ReadValue(&(finfo_.RsvdSecCnt), 1, 14, 2);
  ReadValue(&(finfo_.NumFats), 1, 16, 1);
  ReadValue(&(finfo_.SecPerClus), 1, 13, 1);
  ReadValue(&(finfo_.RootClus), 1, 44, 4);
  ReadValue(&(finfo_.FsInfo), 1, 48, 2);
  ReadValue(&(finfo_.TotSec), 1, 32, 4);

  if (finfo_.BytesPerSec != 512 &&
      finfo_.BytesPerSec != 1024 &&
      finfo_.BytesPerSec != 2048 &&
      finfo_.BytesPerSec != 4096)
    throw std::exception();

  if (finfo_.RootEntCnt != 0)
    throw std::exception();

  if (finfo_.SecPerClus != 1 &&
      finfo_.SecPerClus != 2 &&
      finfo_.SecPerClus != 4 &&
      finfo_.SecPerClus != 16 &&
      finfo_.SecPerClus != 32 &&
      finfo_.SecPerClus != 64 &&
      finfo_.SecPerClus != 128)
    throw std::exception();

  if (finfo_.TotSec == 0)
    throw std::exception();

  finfo_.RootDirSector = ((finfo_.RootEntCnt * 32) + 
                           (finfo_.BytesPerSec - 1)) /
                           finfo_.BytesPerSec;
  finfo_.FATSz = 
        finfo_.FATSz16 != 0 ? finfo_.FATSz16 : finfo_.FATSz32;
  finfo_.FirstDataSec = finfo_.RsvdSecCnt + 
                        (finfo_.NumFats * finfo_.FATSz) +
                        finfo_.RootDirSector;

  if (finfo_.FATSz16 != 0)
    throw std::exception();

  cwd_ = finfo_.RootClus;
  location_ = "/";
}

// Returns string location
std::string Filesys::GetLocation()
{
  return location_;
}

// Returns if there is an error
bool Filesys::HasError()
{
  return error_;
}

// Calls functions and passes them arguements
bool Filesys::CallFunct(std::string& name, 
                        std::vector<std::string>& argv)
{
  try
  {
    functions_.at(name)(*this, argv);
  }
  catch (std::exception &e)
  {
    return false;
  }
  return true;
}

// Gets list of files in specified cluster
// if getDealloc is false, return only allocated files
// if getDealloc is true, return only deallcoated files
// Return value must be deallocated after use
std::list<Filesys::FileEntry>* Filesys::GetFileList(uint32_t cluster, 
                                                    bool getDealloc)
{
  uint32_t entries = finfo_.BytesPerSec * finfo_.SecPerClus / 32;
  uint32_t currentCluster = cluster;
  uint32_t location;

  std::list<FileEntry>* list = new std::list<FileEntry>;

  char name[12];
  uint8_t attr;
  uint16_t lo;
  uint16_t hi;
  uint32_t size;

  name[11] = '\0';

  // Loop through each entry and navigate to next clusters if necessary
  do 
  {
    location = finfo_.BytesPerSec * 
                   finfo_.GetFirstSectorOfClus(currentCluster);

    for (uint32_t i = 0; i < entries; ++i)
    {
      ReadValue(name, 11, location + (32 * i), 1);
      ReadValue(&attr, 1, location + (32 * i) + 11, 1);
      ReadValue(&hi, 1, location + (32 * i) + 20, 2);
      ReadValue(&lo, 1, location + (32 * i) + 26, 2);
      ReadValue(&size, 1, location + (32 * i) + 28, 4);

      if ((attr & LONG) == LONG)
        continue;

      if ((name[0] != 0 && (uint8_t)name[0] != DEALLOC && !getDealloc) ||
          ((name[0] == 0 || (uint8_t)name[0] == DEALLOC) && getDealloc))
      {
        
        FileEntry entry(name, attr, lo, hi, size, location + (32 * i));
        list->push_back(entry);
      }
    }
    currentCluster = GetNextClus(currentCluster);
  } while (currentCluster < FATEND);

  return list;
}

// Reads from filesystem into data
template <typename T>
void Filesys::ReadValue(T* data, size_t len, size_t pos, 
     size_t width)
{
  if (width * len + pos >= filesys_size_)
    throw std::exception();

  for (size_t i = 0; i < len; ++i)
  {
    data[i] = 0;
    for (size_t p = 0; p < width; ++p)
      data[i] |= mFilesys_[pos + (i * width) + p] << (8 * p);
  }
}

// Writes from data to filesystem
template <typename T>
void Filesys::WriteValue(T* data, size_t len, size_t pos, 
                         size_t width)
{
  T tData;
  T mask = 0xFF;

  if (width * len + pos >= filesys_size_)
    throw std::exception();

  for (size_t i = 0; i < len; ++i)
  {
    tData = data[i];
    for (size_t p = 0; p < width; ++p)
    {
      mFilesys_[pos + (i * width) + p] = (uint8_t)(tData & mask);
      tData = tData >> 8;
    }
  }
}

// Writes or reads a file depending on the function passed to it
// Assumes that memory has been allocated for it
uint32_t Filesys::FileOperate(char* stream, uint32_t start, 
     uint32_t length, FileEntry& file, 
     std::function<void (Filesys&, char*, size_t, size_t, size_t)> funct)
{
  uint32_t clusSize = finfo_.BytesPerSec * finfo_.SecPerClus; 

  uint32_t clusNum = start / clusSize;
  uint32_t clusOffset = start % clusSize;
  uint32_t curClus = file.clus;

  for (uint32_t i = 0; i < clusNum; ++i)
  {
    curClus = GetNextClus(curClus);
    if (curClus >= FATEND)
    {
      std::cout << "Error: Start Parameter out of bounds"
                << std::endl;
      return 0;
    }
  }

  uint32_t amountTran = 0;
  uint32_t loc, remaining, tran;

  while (amountTran < length && curClus < FATEND)
  {
    remaining = finfo_.BytesPerSec * finfo_.SecPerClus - 
                clusOffset;
    tran = length - amountTran;
    loc = finfo_.BytesPerSec * 
          finfo_.GetFirstSectorOfClus(curClus);

    if (tran > remaining)
      tran = remaining;

    funct(*this, stream + amountTran, tran, loc + clusOffset, 1);
    amountTran += tran; 
    curClus = GetNextClus(curClus);
    clusOffset = 0;
  }
  return amountTran;
}

// Goes to FAT and returns next cluster in the file
uint32_t Filesys::GetNextClus(uint32_t cluster)
{
  uint32_t entry;
  ReadValue(&entry, 1, finfo_.GetThisFatSecN(cluster) * 
                       finfo_.BytesPerSec + 
                       finfo_.GetThisFatEntOff(cluster), 4);
  return entry & FATMASK;
}

// Goes to FAT and sets cluster, fatLoc specfies the cluster
void Filesys::SetNextClus(uint32_t fatLoc, uint32_t value)
{
  uint32_t entry;
  for (uint8_t i = 0; i < finfo_.NumFats; ++i)
  {
    ReadValue(&entry, 1, (finfo_.GetThisFatSecN(fatLoc) + 
                            (i * finfo_.FATSz)) * 
                         finfo_.BytesPerSec + 
                         finfo_.GetThisFatEntOff(fatLoc), 4);
    entry = entry & (~FATMASK);
    value = value & FATMASK;
    entry = entry | value;
    WriteValue(&value, 1, (finfo_.GetThisFatSecN(fatLoc) + 
                              (i * finfo_.FATSz)) *
                         finfo_.BytesPerSec + 
                         finfo_.GetThisFatEntOff(fatLoc), 4);
  }
}

void Filesys::UpdateClusCount(std::function<uint32_t (uint32_t)> op)
{
  uint32_t clusCount = GetNFreeClus();
  clusCount = op(clusCount);
  SetNFreeClus(clusCount);
}

// Indicates where to begin looking for empty clusters in the FAT
uint32_t Filesys::GetFATNxtFree()
{
  uint32_t value;
  ReadValue(&value, 1, finfo_.BytesPerSec * finfo_.FsInfo + 492, 4);

  return value;
}

// Sets where to begin looking for empty clusters in the FAT
void Filesys::SetFATNxtFree(uint32_t cluster)
{
  WriteValue(&cluster, 1, finfo_.BytesPerSec * finfo_.FsInfo + 492, 4);
}

// Calculates number of free clusters from FsInfo section 
uint32_t Filesys::GetNFreeClus()
{
  uint32_t value;
  ReadValue(&value, 1, finfo_.FsInfo * finfo_.BytesPerSec + 488, 4);
  return value;
}

// Sets number of free clusters from FsInfo section 
void Filesys::SetNFreeClus(uint32_t value)
{
  WriteValue(&value, 1, finfo_.FsInfo * finfo_.BytesPerSec + 488, 4);
}

// Calculation found on page 14 of specification
uint32_t Filesys::Fat32Info::GetFirstSectorOfClus(uint32_t n)
{
  return ((n - 2) * SecPerClus) + FirstDataSec; 
}

// Calculation found on page 15 of specification
uint32_t Filesys::Fat32Info::GetThisFatSecN(uint32_t n)
{
  return RsvdSecCnt + ((n * 4) / BytesPerSec);
}

// Calculation found on page 15 of specification
uint32_t Filesys::Fat32Info::GetThisFatEntOff(uint32_t n)
{
  return (n * 4) % BytesPerSec;
}

// Gets the end of fat
uint32_t Filesys::Fat32Info::GetEndOfFat()
{
  return (TotSec - FirstDataSec) / SecPerClus + 1;
}

Filesys::FileEntry::FileEntry(char* n, uint8_t a, uint16_t l, 
                              uint16_t h, uint32_t s, uint32_t el) :
                            name(n), attr(a), lo(l), hi(h), wrtTime(), 
                            wrtDate(), size(s), clus(), entryLoc(el), 
                            openInfo(0)
{
  // Cluster number broken into two seperate integers, this combines
  // them into one integer
  clus = lo;
  clus |= hi << 16;
}

Filesys::FileEntry::FileEntry(const FileEntry& a) :
                            name(a.name), attr(a.attr), lo(a.lo), 
                            hi(a.hi), size(a.size), clus(a.clus), 
                            entryLoc(a.entryLoc), openInfo(a.openInfo)
{
  // Cluster number broken into two seperate integers, this combines
  // them into one integer
  clus = lo;
  clus |= hi << 16;
}

// Turns short name into lowercase format
// Ex "FILE   PDF" -> "file.pdf"
std::string Filesys::FileEntry::GetShortName()
{
  std::string newName, postfix;
  size_t length = name.length();

  for (size_t i = 0; i < length && i < 8; ++i)
  {
    if (name[i] != ' ')
      newName.push_back(name[i]);
  }

  for (size_t i = 8; i < length && i < 11; ++i)
  {
    if (name[i] != ' ')
      postfix.push_back(name[i]);
  }

  if (postfix.length() != 0)
    newName += "." + postfix;

  std::transform(newName.begin(), newName.end(), newName.begin(), 
                  ::tolower);
  return newName;
}

// Returns true if entry is a directory
bool Filesys::FileEntry::IsDir()
{
  if ((attr & DIRECT) == DIRECT) 
    return true;
  else
    return false;
}

// Sets the time field
void Filesys::FileEntry::SetCurrentTime()
{
  time_t timer;
  struct tm* localTime;

  time(&timer);
  localTime = localtime(&timer);
  
  wrtDate = localTime->tm_mday;
  wrtDate |= ((localTime->tm_mon + 1) << 5);
  wrtDate |= ((localTime->tm_year - 80) << 9);

  uint8_t tValue = localTime->tm_sec / 2;
  wrtTime = tValue > 29 ? 29 : tValue;
  wrtTime |= (localTime->tm_min << 5);
  wrtTime |= (localTime->tm_hour << 11);
}

// Sets the Cluster information for the file entry
void Filesys::FileEntry::SetClus(uint32_t cluster)
{
  clus = cluster;
  hi = (cluster & 0xFFFF0000) >> 4;
  lo = cluster & 0x0000FFFF;
}

// Breaks up address into list of locations
// Ex /exdir/test/file -> list {exdir, test, file}
std::list<std::string> Filesys::ParseAddress(std::string add)
{
  std::list<std::string> list;
  if (add.size() != 0)
  {
    size_t start = 0;
    size_t end;
    
    std::transform(add.begin(), add.end(), add.begin(), 
                  ::tolower);

    if (add[0] == '/')
    {
      list.push_back("/");
      start = 1;
    }

    while((end = add.find_first_of("/", start)) != 
                                                 std::string::npos)
    {
      if (start - end != 0)
      {
          list.push_back(add.substr(start, end - start));
      }

      start = end + 1;
    }

    if (start < add.size())
      list.push_back(add.substr(start));
  }

  return list;
}

// Takes list of locations from ParseAddress and returns the cluster
// of the final location. Start and end specifices the range in the 
// list to navigate. End is not inclusive, start is inclusive
uint32_t Filesys::NavToDir(std::list<std::string>& list, size_t start, 
                           size_t end)
{
  uint32_t currDirClus = cwd_;
  bool found;

  // Nowhere to navigate
  if (start - end == 0)
    return currDirClus;

  // Nowhere to navigate
  if (list.size() == 0)
    throw std::exception();

  size_t i = start;
  for (std::string item : list)
  {
    if (i == end)
      break;

    if (i == 0 && item == "/")
    {
      // Start at root
      currDirClus = finfo_.RootClus;
    }
    else if (item != "." || currDirClus != finfo_.RootClus)
    {
      // Will not enter here if . and in root dir because there is no
      // . in that directory
      std::list<FileEntry>* entries = GetFileList(currDirClus);
      found = false;

      for (FileEntry e : *entries)
      {
        if (e.GetShortName() == item && e.IsDir())
        {
          // .. in level below root has clus of 0
          if (e.clus == 0 && item == "..")
            currDirClus = finfo_.RootClus;
          else
          {
            currDirClus = e.clus;
          }

          found = true;
          break;
        }
      }

      delete entries;

      if (found == false)
      {
        throw std::exception();
      }
    }
    ++i;
  }
  return currDirClus;
}

// Gets the path name to a cluster
std::string Filesys::GenPathName(uint32_t clus)
{
  std::string name;
  uint32_t curClus = cwd_;
  uint32_t prevClus = clus;
  uint32_t foundClus = clus;
  std::list<FileEntry>* list;

  while(curClus != finfo_.RootClus)
  {
    curClus = foundClus;
    list = GetFileList(curClus);

    for (FileEntry e : *list)
    {
      if (e.GetShortName() == "..")
      {
        if (e.clus == 0)
          foundClus = finfo_.RootClus;
        else
          foundClus = e.clus;
      }

      if (prevClus == e.clus && e.GetShortName() != ".")
      {
        if (name.length() == 0)
          name = e.GetShortName();
        else
          name = e.GetShortName() + "/" + name;
        prevClus = curClus;
      }
    }
    delete list;
  }

  return "/" + name;
}

// Saves FileEntry
void Filesys::SaveFileEntry(FileEntry& entry)
{
  uint32_t loc = entry.entryLoc; 
  uint32_t zero = 0;
  char name[11];

  for (int i = 0; i < 11; ++i)
    name[i] = entry.name[i];

  entry.SetCurrentTime();

  WriteValue(name, 11, loc , 1);
  WriteValue(&(entry.attr), 1, loc + 11, 1);
  WriteValue(&zero, 1, loc + 13, 1);
  WriteValue(&zero, 1, loc + 14, 2);
  WriteValue(&zero, 1, loc + 16, 2);
  WriteValue(&zero, 1, loc + 18, 2);
  WriteValue(&(entry.hi), 1, loc + 20, 2);
  WriteValue(&(entry.wrtTime), 1, loc + 22, 2);
  WriteValue(&(entry.wrtDate), 1, loc + 24, 2);
  WriteValue(&(entry.lo), 1, loc + 26, 2);
  WriteValue(&(entry.size), 1, loc + 28, 4);
}

// Validates file name according to specifications
std::string Filesys::ValidateFileName(std::string name)
{
  size_t invalidChars = name.find_first_of("/ \"*+`-;:<>=?", 0);

  if (invalidChars != std::string::npos)
  {
    std::cout << "Invalid Filename" << std::endl;
    throw std::exception();
  }

  size_t dotPos = name.find_first_of(".", 0);
  char fixedName[12];
  fixedName[11] = '\0';

  std::string originalName = name;

  if (dotPos == 0 || dotPos == name.length() - 1)
  {
    std::cout << "Invalid Filename" << std::endl;
    throw std::exception();
  }

  if (dotPos != std::string::npos)
  {
    if (name.length() - (dotPos + 1) > 3)
    {
      std::cout << "Invalid Filename" << std::endl;
      throw std::exception();
    }

    std::string postfix = name.substr(dotPos + 1, name.length());
    name = name.substr(0, dotPos);

    for (size_t i = 0; i < 8; ++i)
    {
      if (i >= name.length()) 
        fixedName[i] = ' ';
      else
        fixedName[i] = name[i];
    }
    for (size_t i = 8; i < 11; ++i)
    {
      if (i - 8 >= postfix.length())
        fixedName[i] = ' ';
      else
        fixedName[i] = postfix[i - 8];
    }
  }
  else
  {
    if (name.length() > 8)
    {
      std::cout << "Invalid Filename" << std::endl;
      throw std::exception();
    }

    for (size_t i = 0; i < 11; ++i)
    {
      if (i >= name.length())
        fixedName[i] = ' ';
      else
        fixedName[i] = name[i];
    }
  }

  std::string output(fixedName);
  return output;
}

// Allocates a cluster and returns the new cluster number
// location is optional, if tihs cluster value is passed in
// then the new cluster is appened to chain at location
uint32_t Filesys::AllocateCluster(uint32_t location)
{
  // Allocate new cluster
  uint32_t position = GetFATNxtFree();
  uint32_t entryValue;
  bool found = false;
  int startFromTop = 0;
  uint32_t endOfFat = finfo_.GetEndOfFat();

  if (position == 0xFFFFFFFF)
  {
    // Start at cluster 2 if no hint
    position = 2;
    startFromTop = 1;
  }

  do
  {
    do
    {
      entryValue = GetNextClus(position);
      if (entryValue == 0)
      {
        found = true;
        break;
      }
      ++position;
    } while (position < endOfFat);

    ++startFromTop;

    if (!found) 
      position = 2;
  }
  while (!found && startFromTop < 2);

  if (!found)
  {
    std::cout << "Filesystem out of space" << std::endl;
    return 0;
  } 

  // This appends the new cluster to the end of a chain if location is set
  if (location != 0)
  {
    uint32_t templocat = location;
    while (1) 
    {
      if ((templocat = GetNextClus(templocat)) >= FATEND)
        break;

      location = templocat;
    }
    SetNextClus(location, position);
  }

  SetNextClus(position, 0xFFFFFFFF);
  SetFATNxtFree(position);
  UpdateClusCount([] (uint32_t value) { return value - 1;});
  ZeroOutCluster(position);

  return position;
}

// Zeroes out the speciied cluster
void Filesys::ZeroOutCluster(uint32_t cluster)
{
  uint32_t start = finfo_.BytesPerSec * 
                   finfo_.GetFirstSectorOfClus(cluster);
  uint32_t len = finfo_.BytesPerSec * finfo_.SecPerClus;
  uint8_t zero = 0;

  for (uint32_t i = 0; i < len; ++i)
    WriteValue(&zero, 1, start + i, 1); 
}

// Allocates space for a FileEntry, does not actually save it
Filesys::FileEntry* Filesys::AddEntry(uint32_t location, std::string name,
                                      uint8_t attr)
{
  std::list<FileEntry>* list = GetFileList(location);

  for (FileEntry e : *list)
  {
    if (e.GetShortName() == name)
    {
      std::cout << "File Already Exists" << std::endl;
      delete list;
      return NULL;
    }
  }

  delete list;
  list = GetFileList(location, true);

  if (list->size() == 0)
  {
    delete list;
    if (AllocateCluster(location) == 0)
      return NULL;
    list = GetFileList(location, true);
  }

  FileEntry entry = list->front();

  char value[12];
  value[11] = '\0';
  std::transform(name.begin(), name.end(), name.begin(), 
                ::toupper);

  for (size_t i = 0; i < 11; ++i)
  {
    if (i >= name.length())
      value[i] = ' ';
    else
      value[i] = name[i];
  }

  entry.name = value;
  entry.attr = attr;
  entry.SetClus(0);
  entry.size = 0;

  delete list;
  return new FileEntry(entry);
}

void Filesys::Fsinfo(std::vector<std::string>& argv)
{
  if (argv.size() != 0)
  {
    std::cout << "usage: fsinfo" << std::endl;
    return;
  }
  else
  {
    uint32_t sec = GetNFreeClus() * finfo_.SecPerClus;
    std::cout << "  Bytes Per Sector:       " << finfo_.BytesPerSec <<
    std::endl << "  Sectors Per Cluster:    " << finfo_.SecPerClus <<
    std::endl << "  Total Sectors:          " << finfo_.TotSec <<
    std::endl << "  Number of FATs:         " << finfo_.NumFats <<
    std::endl << "  Sectors Per Fat:        " << finfo_.FATSz32 <<
    std::endl << "  Number of Free Sectors: " << sec <<
    std::endl;
  }
}

void Filesys::Ls(std::vector<std::string>& argv)
{
  std::string target;
  uint32_t currDirClus = cwd_;

  if (argv.size() < 1)
  {
    target = ".";
  }
  else if (argv.size() == 1)
  {
    target = argv[0];
  }
  else
  {
    std::cout << "usage: ls [directory_name]" << std::endl;
    return;
  }

  std::list<std::string> list = ParseAddress(target);

  try
  {
    currDirClus = NavToDir(list, 0, list.size());
  }
  catch(std::exception &e)
  {
    std::cout << "Error: Invalid Directory" << std::endl;
    return;
  }

  if (currDirClus == 0)
    return;

  std::list<FileEntry>* display = GetFileList(currDirClus);

  for (FileEntry i : *display)
  {
    std::cout << i.GetShortName() << " ";
  }

  if (display->size() > 0)
    std::cout << std::endl;

  delete display;
}

void Filesys::Cd(std::vector<std::string>& argv)
{
  std::string target;
  uint32_t currDirClus = cwd_;

  if (argv.size() < 1)
  {
    target = "/";
  }
  else if (argv.size() == 1)
  {
    target = argv[0];
  }
  else
  {
    std::cout << "usage: cd [directory_name]" << std::endl;
    return;
  }

  std::list<std::string> list = ParseAddress(target);

  try
  {
    currDirClus = NavToDir(list, 0, list.size());
  }
  catch(std::exception &e)
  {
    std::cout << "Error: Invalid Directory" << std::endl;
    return;
  }

  cwd_ = currDirClus;
  location_ = GenPathName(cwd_);
}

void Filesys::Size(std::vector<std::string>& argv)
{
  if (argv.size() != 1)
  {
    std::cout << "usage: size <entry_name>" << std::endl;
    return;
  }
  else
  {
    std::list<std::string> address = ParseAddress(argv[0]);
    uint32_t location = cwd_;

    try
    {
      location = NavToDir(address, 0, address.size() - 1);
    }
    catch (std::exception &e)
    {
      std::cout << "Invalid directory" << std::endl;
    }

    std::list<FileEntry>* list = GetFileList(location);
    std::string name = address.back();

    bool found = false;

    for (FileEntry e : *list)
    {
      if (e.GetShortName() == name)
      {
        uint32_t currentCluster = e.clus;
        size_t count = 0;

        do
        {
          currentCluster = GetNextClus(currentCluster);
          ++count;
        } while (currentCluster < FATEND);

        std::cout << count * finfo_.BytesPerSec * finfo_.SecPerClus
        << std::endl;
        found = true;
        break;
      }
    }

    if (!found)
      std::cout << "Invalid Filename" << std::endl;

    delete list;
  }
}

void Filesys::Open(std::vector<std::string>& argv)
{
  if (argv.size() != 2)
  {
    std::cout << "usage: open <file_name> <mode>" << std::endl;
    return;
  }
  else
  {
    std::string name = argv[0];
    uint32_t location = cwd_;
    uint32_t openPermission = 0;

    if (argv[1] == "rw")
    {
      openPermission = READ | WRITE;
    }
    else if (argv[1] == "r")
    {
      openPermission = READ;
    }
    else if (argv[1] == "w")
    {
      openPermission = WRITE;
    }
    else
    {
      std::cout << "Invalid Permission" << std::endl;
      return;
    }

    std::list<FileEntry>* list = GetFileList(location);
    bool found = false;

    for (FileEntry e : openTable_)
    {
      if (e.GetShortName() == name)
      {
        std::cout << "File Already Open" << std::endl;
        delete list;
        return;
      }
    }

    for (FileEntry e : *list)
    {
      if (e.GetShortName() == name)
      {
        if ((e.attr & DIRECT) ==  DIRECT)
        {
          std::cout << "Error: Cannot Open Directory" << std::endl;
          delete list;
          return;
        }
        e.openInfo = openPermission;
        openTable_.push_back(e);
        found = true;
        break;
      }
    }

    if (!found)
      std::cout << "Invalid Filename" << std::endl;

    delete list;
  }
}

void Filesys::Close(std::vector<std::string>& argv)
{
  if (argv.size() != 1)
  {
    std::cout << "Usage: Close <file_name>" << std::endl;
    return;
  }
  else
  {
    std::list<FileEntry>::iterator iter = openTable_.begin(); 
    std::string name = argv[0];

    while (iter != openTable_.end())
    {
      if ((*iter).GetShortName() == name)
      {
        openTable_.erase(iter);
        return;
      }
      ++iter;
    }
    std::cout << "File not open" << std::endl;
  }
}

void Filesys::Read(std::vector<std::string>& argv)
{
  if (argv.size() != 3)
  {
    std::cout << "Usage: Read <file_name> <start> <num_bytes>"
              << std::endl;
    return;
  }
  else
  {
    std::list<FileEntry>::iterator iter = openTable_.begin(); 
    std::string name = argv[0];
    bool found = false;

    while (iter != openTable_.end())
    {
      if ((*iter).GetShortName() == name)
      {
        if (((*iter).openInfo & READ) != READ)
        {
          std::cout << "Error: File not open for reading" 
                    << std::endl;
          return;
        }

        found = true;
        break;
      }
      ++iter;
    }

    if (!found)
    {
      std::cout << "Error: File not open" << std::endl;
      return;
    }

    // May need to validate to ensure arguments are numbers

    uint32_t start = std::stoi(argv[1]);
    uint32_t length = std::stoi(argv[2]);
    char* readIn = new char[length + 1];
    readIn[length] = '\0';
    uint32_t amountRead = FileOperate(readIn, start, length, *iter, 
              &Filesys::ReadValue<char>);
    for (uint32_t i = 0; i < amountRead; ++i)
    {
      std::cout << readIn[i];
    }

    delete[] readIn;
  }
}

void Filesys::Write(std::vector<std::string>& argv)
{
  if (argv.size() != 3)
  {
    std::cout << "Usage: Write <file_name> <start> <quoted_data>"
              << std::endl;
    return;
  }
  else
  {
    std::list<FileEntry>::iterator iter = openTable_.begin(); 
    std::string name = argv[0];
    bool found = false;

    while (iter != openTable_.end())
    {
      if ((*iter).GetShortName() == name)
      {
        if (((*iter).openInfo & WRITE) != WRITE)
        {
          std::cout << "Error: File not open for writing" 
                    << std::endl;
          return;
        }

        found = true;
        break;
      }
      ++iter;
    }

    if (!found)
    {
      std::cout << "Error: File not open" << std::endl;
      return;
    }

    // May need to validate to ensure arguments are numbers

    uint32_t start = std::stoi(argv[1]);
    std::string input = argv[2];
    uint32_t length = input.length();

    uint32_t totalSize = start + length;
    uint32_t currAllocated;
    uint32_t location;

    if ((*iter).clus == 0)
    {
      location = AllocateCluster();
      (*iter).SetClus(location);
      (*iter).size = totalSize;
      SaveFileEntry(*iter);
      currAllocated = 1;
    }
    else
    {
      currAllocated = 0;
      location = (*iter).clus;
      uint32_t templocat = location;
      while (1) 
      {
        ++currAllocated;
        if ((templocat = GetNextClus(templocat)) >= FATEND)
          break;

        location = templocat;
      }
    }
    currAllocated *= finfo_.SecPerClus * finfo_.BytesPerSec;


    if (totalSize > currAllocated)
    {
      uint32_t neededClus = 
                  (uint32_t)ceil((float)(totalSize - currAllocated) /
                  (finfo_.SecPerClus * finfo_.BytesPerSec));

      for (uint32_t i = 0; i < neededClus; ++i)
      {
        location = AllocateCluster(location);
      }
    }

    if ((*iter).size < totalSize)
    {
      (*iter).size = totalSize;
      SaveFileEntry(*iter);
    }

    char* writeIn = new char[length + 1];
    writeIn[length] = '\0';

    strcpy(writeIn, input.c_str());
    if (FileOperate(writeIn, start, length, *iter, 
              &Filesys::WriteValue<char>) == 0)
    {
      std::cout << "An error occured" << std::endl;
    }

    delete[] writeIn;
  }
}

void Filesys::Mkdir(std::vector<std::string>& argv)
{
  if (argv.size() != 1)
  {
    std::cout << "Usage: mkdir <dir_name>" << std::endl;
    return;
  }
  else
  {
    std::list<std::string> address = ParseAddress(argv[0]);
    uint32_t location = cwd_;

    try
    {
      location = NavToDir(address, 0, address.size() - 1);
    }
    catch (std::exception &e)
    {
      std::cout << "Invalid location" << std::endl;
      return;
    }

    std::string name = address.back();

    std::string fixedName; 
    try
    {
      fixedName = ValidateFileName(name);
    }
    catch(std::exception &e)
    {
      return;
    }

    // Other Validations needed
    FileEntry* entry = AddEntry(location, name, DIRECT);

    if (entry != NULL)
    {
      uint32_t newCluster = AllocateCluster();
      if (newCluster != 0)
      {
        entry->SetClus(newCluster);
        entry->name = fixedName;
        FileEntry* level = AddEntry(entry->clus,".          ", DIRECT);
        FileEntry* topLevel = AddEntry(entry->clus,"..         ", DIRECT);

        if (level != NULL)
        {
          level->SetClus(newCluster);
          SaveFileEntry(*level);
          delete level;
        }
        if (topLevel != NULL)
        {
          topLevel->SetClus(location == finfo_.RootClus ? 0 : location);
          topLevel->entryLoc += 32;
          SaveFileEntry(*topLevel);
          delete topLevel;
        }
        SaveFileEntry(*entry);
      }
      delete entry;
    }
  }
}

void Filesys::Create(std::vector<std::string>& argv)
{
  if (argv.size() != 1)
  {
    std::cout << "Usage: create <file_name>" << std::endl;
    return;
  }
  else
  {
    std::list<std::string> address = ParseAddress(argv[0]);
    uint32_t location = cwd_;

    try
    {
      location = NavToDir(address, 0, address.size() - 1);
    }
    catch (std::exception &e)
    {
      std::cout << "Invalid location" << std::endl;
    }

    std::string name = address.back();
    
    std::string fixedName; 
    try
    {
      fixedName = ValidateFileName(name);
    }
    catch(std::exception &e)
    {
      return;
    }

    FileEntry* entry = AddEntry(location, name, 0);

    if (entry != NULL)
    {
      entry->SetClus(0);
      entry->name = fixedName;
      SaveFileEntry(*entry);
      delete entry;
    }
  }
}

void Filesys::Undelete(std::vector<std::string>&)
{
  uint32_t location = cwd_;
  uint32_t endOfFat = finfo_.GetEndOfFat();
  uint32_t maxCount = 99;
  uint16_t count = 0;

  std::list<FileEntry>* allist = GetFileList(location);

  for (FileEntry e : *allist)
  {
    if (e.GetShortName().substr(0, 6) == "recvd_")
      ++count;
  }

  delete allist;

  if (count > maxCount)
    return;

  std::list<FileEntry>* delist = GetFileList(location, true);

  for (FileEntry e : *delist)
  {
    if ((unsigned char)e.name[0] == 0xe5)
    {
      uint32_t clusterCount = 1;

      if ((e.attr & DIRECT) != DIRECT)
      {
        clusterCount = ceil((float)e.size / (finfo_.BytesPerSec * 
                                             finfo_.SecPerClus));
      }

      uint32_t currentCluster = e.clus;
      uint32_t nextCluster;
      bool boundError = false;

      if (currentCluster != 0)
      {
        while (GetNextClus(currentCluster) != 0)
        {
          ++currentCluster;
          if (currentCluster > endOfFat)
          {
            boundError = true;
            break;
          }
        }

        nextCluster = currentCluster + 1;

        if (boundError)
          continue;

        e.clus = currentCluster;

        for (uint32_t i = 0; i < clusterCount; ++i)
        {
          if (i == clusterCount - 1)
          {
            SetNextClus(currentCluster, 0xFFFFFFFF);
            UpdateClusCount([] (uint32_t value) {return value - 1;});
          }
          else
          {
            while (GetNextClus(nextCluster) != 0)
            {
              ++nextCluster;
              if (nextCluster > endOfFat)
              {
                boundError = true;
                break;
              }
            }

            if (boundError)
              break;
            SetNextClus(currentCluster, nextCluster);
            UpdateClusCount([] (uint32_t value) {return value - 1;});
            currentCluster = nextCluster;
            ++nextCluster;
          }
        }
      }

      ++count;
      std::ostringstream number;
      number << "RECVD_" <<  count;
      size_t padding = 11 - number.str().length();
      e.name = number.str();

      for (size_t i = 0; i < padding; ++i)
        e.name += ' ';

      SaveFileEntry(e);

      if (count >= maxCount)
        break;
    }
  }
  delete delist;
}

void Filesys::Rm(std::vector<std::string>& argv)
{
  uint32_t location = cwd_;

  if (argv.size() == 0)
  {
    std::cout << "Usage: rm <file_name>\n";
    return;
  }

  // maybe have code to parse the input in case file has leading dir
  // for loop to allow removing multiple files at once
  for (uint32_t i=0; i < argv.size(); i++)
  {
    std::list<FileEntry>::iterator iter = openTable_.begin();
    std::string name = argv[i];

    // to check if file is open, and closing befire removing
    while(iter != openTable_.end())
    {
      if ((*iter).GetShortName() == name)
      {
        std::vector<std::string> list;
        list.push_back(argv[i]);
        Close(list);
        break;
      }
      iter++;
    }

    std::list<FileEntry>* list = GetFileList(location);
    uint32_t count = 0;
    bool found = false;

    for (FileEntry e : *list)
    {
      if (e.GetShortName() == name)
      {
        if ((e.attr & DIRECT) == DIRECT)
          continue;

        found = true;

        if (e.clus != 0)
        {
          uint32_t currCluster = e.clus;
          uint32_t lastCluster;

          do
          {
            lastCluster = currCluster;
            currCluster = GetNextClus(currCluster);
            SetNextClus(lastCluster, 0);
            UpdateClusCount([] (uint32_t value) { return value + 1;});
            count++;
          } while (currCluster < FATEND);
        } 
        
        e.name[0] = 0xe5;
        SaveFileEntry(e);
        break;
      }
      iter++;
    }

    delete list;

    if (!found)
    {
      std::cout << "File " << name << " not found!\n";
      return;
    }

  }
}

void Filesys::Rmdir(std::vector<std::string>& argv)
{
  if (argv.size() != 1)
  {
    std::cout << "usage: rmdir <dir_name>" << std::endl;
    return;
  }
  else
  {
    std::string name = argv[0];
    uint32_t location = cwd_;
    std::list<FileEntry>* list = GetFileList(location);
    FileEntry* entry = NULL;

    bool found = false;
    if (name[0] != '.')
    {
      for (FileEntry e : *list)
      {
        if (e.GetShortName() == name)
        {
          if ((e.attr & DIRECT) == DIRECT)
          {
            found = true;
            entry = new FileEntry(e);
          }
          break;
        }
      }
    }

    delete list;

    if (!found)
    {
      std::cout << "Invalid Filename" << std::endl;
      return;
    }

    list = GetFileList(entry->clus);
    
    if (list->size() > 2)
    {
      std::cout << "Directory must be empty" << std::endl;
      delete list;
      delete entry;
      return;
    }

    entry->name[0] = 0xe5;
    SaveFileEntry(*entry);

    if (entry->clus != 0)
    {
      uint32_t currCluster = entry->clus;
      uint32_t lastCluster;

      do
      {
        lastCluster = currCluster;
        currCluster = GetNextClus(currCluster);
        SetNextClus(lastCluster, 0);
        UpdateClusCount([] (uint32_t value) { return value + 1;});
      } while (currCluster < FATEND);
    }

    delete entry;
    delete list;
  }
}

void Filesys::Help(std::vector<std::string>&)
{
  std::cout << " Enter any of the following commands:" << std::endl;
  for (auto item : functions_)
  {
    std::cout << "   " << item.first << std::endl;
  }
}
