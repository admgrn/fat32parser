#include <filesys.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <initializer_list>
#include <cctype>
#include <algorithm>

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

  // Open File Descripter
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
  functions_.insert(std::make_pair("mkdir", &Filesys::Mkdir));
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
  ReadValue(&(finfo_.SecPerFat), 1, 32, 4);

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

// Goes to FAT and returns next cluster in the file
uint32_t Filesys::GetNextClus(uint32_t cluster)
{
  uint32_t entry;
  ReadValue(&entry, 1, finfo_.GetThisFatSecN(cluster) * 
                       finfo_.BytesPerSec + 
                       finfo_.GetThisFatEntOff(cluster), 4);
  return entry & FATMASK;
}

// Calculates number of free clusters from FsInfo section 
uint32_t Filesys::GetNFreeClus()
{
  uint32_t value;
  ReadValue(&value, 1, finfo_.FsInfo * finfo_.BytesPerSec + 488, 4);
  return value;
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

Filesys::FileEntry::FileEntry(char* n, uint8_t a, uint16_t l, 
                              uint16_t h, uint32_t s, uint32_t el) :
                            name(n), attr(a), lo(l), hi(h), size(s),
                            clus(), entryLoc(el), openInfo(0)
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
            currDirClus = e.clus;

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
  uint32_t curClus;
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

// Creates and empty file
void Filesys::CreateFile(char* name, uint8_t attr, uint32_t loc)
{
  uint32_t zero = 0;
  WriteValue(name, 11, loc , 1);
  WriteValue(&attr, 1, loc + 11, 1);
  WriteValue(&zero, 1, loc + 20, 2);
  WriteValue(&zero, 1, loc + 26, 2);
  WriteValue(&zero, 1, loc + 28, 4);
}

void Filesys::CreateEntry(uint32_t location, std::string name,
                          uint8_t attr)
{
  std::list<FileEntry>* list = GetFileList(location);

  for (FileEntry e : *list)
  {
    if (e.GetShortName() == name)
    {
      std::cout << "File Already Exists" << std::endl;
      delete list;
      return;
    }
  }

  delete list;
  list = GetFileList(location, true);
  uint32_t offset;

  if (list->size() == 0)
  {
    // Allocate new cluster
    std::cout << "Need to allcoate new cluster" << std::endl;
  }
  else
  {
    offset = list->front().entryLoc;
  }

  char value[11];
  std::transform(name.begin(), name.end(), name.begin(), 
                ::toupper);

  for (size_t i = 0; i < 11; ++i)
  {
    if (i >= name.length())
      value[i] = ' ';
    else
      value[i] = name[i];
  }

  CreateFile(value, attr, offset);

  delete list;
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
    char* readIn = new char[length];
    uint32_t clusSize = finfo_.BytesPerSec * finfo_.SecPerClus; 

    uint32_t clusNum = start / clusSize;
    uint32_t clusOffset = start % clusSize;
    uint32_t curClus = (*iter).clus;

    for (uint32_t i = 0; i < clusNum; ++i)
    {
      curClus = GetNextClus(curClus);
      if (curClus >= FATEND)
      {
        delete readIn;
        std::cout << "Error: Start Parameter out of bounds"
                  << std::endl;
        return;
      }
    }

    uint32_t amountRead = 0;
    uint32_t loc, remaining, read;

    while (amountRead < length && curClus < FATEND)
    {
      remaining = finfo_.BytesPerSec * finfo_.SecPerClus - 
                  clusOffset;
      read = length - amountRead;
      loc = finfo_.BytesPerSec * 
            finfo_.GetFirstSectorOfClus(curClus);

      if (read > remaining)
        read = remaining;

      ReadValue(readIn + amountRead, read, loc + clusOffset, 1);
      amountRead += read; 
      curClus = GetNextClus(curClus);
      clusOffset = 0;
    }

    for (uint32_t i = 0; i < amountRead; ++i)
    {
      std::cout << readIn[i];
    }
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
    }

    std::string name = address.back();
    
    if (name.length() > 7)
    {
      std::cout << "Filename too long" << std::endl;
      return;
    }

    // Other Validations needed
    CreateEntry(location, name, DIRECT);
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
