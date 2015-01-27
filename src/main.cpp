#include <filesys.h>
#include <iostream>
#include <string>
#include <sstream>

int main (int argc, char* argv[])
{
  if (argc == 2)
  {
    std::string filename = argv[1];
    Filesys file(filename);

    if (file.HasError())
    {
      std::cout << "Error: Unrecognized file name" << std::endl;
      return 1;
    }

    try
    {
      file.Validate();
    }
    catch (std::exception &e)
    {
      std::cout << "Invalid image" << std::endl;
      return 1;
    }

    try
    {
      while (1)
      {
        std::string input;

        std::cout << "Enter command or exit : " << file.GetLocation() << " > ";
        std::getline(std::cin, input);

        if (input == "exit")
          break;

        std::vector<std::string> argv;
        std::string name;
        std::string temp;
        int c = -1;
        bool newWord = false;
        bool lookForEndQuote = false;

        for (size_t i = 0; i < input.length(); ++i)
        {
          if (((input[i] == ' ' || input[i] == '\t') && !lookForEndQuote) ||
              (lookForEndQuote && input[i] == '"') ||
              (newWord && input[i] == '"' && !lookForEndQuote))
          {
            if (!newWord)
            {
              newWord = true;
              ++c;
            }

            if (lookForEndQuote && input[i] == '"')
              lookForEndQuote = false;
            else if (input[i] == '"')
              lookForEndQuote = true;

            continue;
          }

          if (c == -1)
          {
            name.push_back(input[i]);
          }
          else
          {
            if (newWord)
            {
              newWord = false;
              argv.push_back("");
            }

            argv.back().push_back(input[i]);
          }
        }

        if (!lookForEndQuote)
        {
          if (name == "")
            continue;

          if (!file.CallFunct(name, argv))
            std::cout << "Invalid command" << std::endl;
        }
        else
        {
          std::cout << "Error: Unclosed Quote" << std::endl;
        }
      }
    }
    catch (std::exception &e)
    {
      std::cout << "An error occured" << std::endl;
      return 1;
    }
  }
  else
  {
    std::cout << "Usage: " << argv[0] << " <file system>" << std::endl;
    return 1;
  }

  return 0;
}
