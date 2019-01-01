#include <errno.h>
#include <seccomp.h>
#include <iostream>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sstream>
#include <iomanip>
#include <vector>

using namespace std;

const int NUM_SYSCALLS = 330;

void printJsonOutput(string &sReadMsg, bool &bFirstResult)
{

  size_t last = 0;
  size_t next = 0;
  std::vector<string> vResults;

  while ((next = sReadMsg.find("|", last)) != string::npos)
  {
    // cout << sReadMsg.substr(last, next - last) << endl;
    vResults.push_back(sReadMsg.substr(last, next - last));
    last = next + 1;
  }
  vResults.push_back(sReadMsg.substr(last));
  // cout << sReadMsg.substr(last) << endl;

  // idx, name, sStatus.c_str(), strerror(errno), errno);
  if (bFirstResult)
  {
    cout << "  {" << endl;
    bFirstResult = false;
  }
  else
  {
    cout << "," << endl
         << "  {" << endl;
  }
  for (auto idx = 0; idx < vResults.size(); idx++)
  {
    switch (idx)
    {
    case 0:
      cout << "    "
           << "\"number\":"
           << " \"" << vResults[idx] << "\"," << endl;
      break;
    case 1:
      cout << "    "
           << "\"name\":"
           << " \"" << vResults[idx] << "\"," << endl;
      break;
    case 2:
      cout << "    "
           << "\"status\":"
           << " \"" << vResults[idx] << "\"," << endl;
      break;
    case 3:
      cout << "    "
           << "\"errmsg\":"
           << " \"" << vResults[idx] << "\"," << endl;
      break;
    case 4:
      cout << "    "
           << "\"errno\":"
           << " \"" << vResults[idx] << "\"" << endl;
      break;
    }
    // cout << vResults[idx] << "\n";
  }

  cout << "  }";
}

int Usage(char *ProgramName)
{
  cout << endl;
  cout << "Usage: " << ProgramName << " [-f] [-a]" << endl
       << "    or " << ProgramName << endl;
  cout << "  -f     Show only filtered syscalls" << endl;
  cout << "  -a     Show only allowed syscalls" << endl;
  cout << endl;
  cout << "NOTE: By default, both allowed and filtered syscalls are returned"
       << endl;
  return -1;
}

int main(int argc, char *argv[])
{
  unsigned int pid, idx;
  int ret;

  int arg;
  bool bFiltered = false;
  bool bAllowed = false;
  bool bUnknownParam = false;

  if (argc > 3)
  {
    return Usage(argv[0]);
  }

  if (argc > 1)
  {
    for (arg = 1; arg < argc; arg++)
    {
      switch (argv[arg][0])
      {

      case L'-':
      case L'/':
        switch (argv[arg][1])
        {
        case L'?':
          return Usage(argv[0]);
        case L'h':
          return Usage(argv[0]);
        case L'f': // filtered syscalls
        case L'F':
          bFiltered = true;
          break;
        case L'a': // allowed syscalls
        case L'A':
          bAllowed = true;
          break;
        default:
          bUnknownParam = true;
          break;
        }
        break;
      }
    }
  }

  if (bUnknownParam)
  {
    return Usage(argv[0]);
  }

  if ((!bFiltered) && (!bAllowed))
  {
    // means no params passed. Assume default of printing both
    bFiltered = true;
    bAllowed = true;
  }

  for (idx = 0; idx <= NUM_SYSCALLS; idx++)
  {
    pid = fork();
    if (!pid)
    { // child
      auto arch = seccomp_arch_native();
      auto *name = seccomp_syscall_resolve_num_arch(arch, idx);

      bool bCallFiltered = false;
      bool bCallAllowed = false;

      // these cause a hang, so just skip
      if (idx == SYS_pause) {
        exit(0);
      }
      if (idx == SYS_rt_sigreturn) {
        exit(0);
      }
      if (idx == SYS_select) {
        exit(0);
      }
      if (idx == SYS_pselect6) {
        exit(0);
      }
      if (idx == SYS_ppoll) {
        exit(0);
      }

      // exit_group and exit -- causes us to exit
      if (idx == SYS_exit) {
        exit(0);
      }
      if (idx == SYS_exit_group) {
        exit(0);
      }

      // things currently break horribly if  CLONE, FORK or VFORK are called and the call succeeds
      // guess it should be straight forward to kill the forks
      //if (idx == SYS_clone) {exit(0);}
      //if (idx == SYS_fork) {exit(0);}
      //if (idx == SYS_vfork) {exit(0);}
      ret = syscall(idx, 0, 0, 0);

      // check both EPERM and EACCES - LXC returns EACCES and Docker EPERM
      std::string sStatus;
      if ((ret == EPERM) || (ret == EACCES))
      {
        // cerr << "blocked" << endl;
        sStatus = "filtered";
        bCallFiltered = true;
      }
      else
      {
        // cerr << "allowed" << endl;
        sStatus = "allowed";
        bCallAllowed = true;
      }

      std::ostringstream ssMessage;
      ssMessage << std::setw(3) << std::setfill('0') << idx << "|"
                << name << "|"
                << sStatus << "|"
                << strerror(errno) << "|"
                << errno;
      std::string sReadMsg = ssMessage.str();
      //printf(" -- syscall(%u) is %s = %d : %s (%d)\n", idx, name, ret, strerror(errno), errno);

      if ((bFiltered) && (bAllowed))
      {
        cout << sReadMsg << endl;
      }
      else
      {
        if (bFiltered) {
          //if (sReadMsg.find("|filtered|") != std::string::npos) {
          if (bCallFiltered) {
            cout << sReadMsg << endl;
          }
        }
        if (bAllowed) {
          //if (sReadMsg.find("|allowed|") != std::string::npos) {
          if (bCallAllowed) {
            cout << sReadMsg << endl;
          }
        }
      }

      exit(0);
    }
    else
    {
      usleep(100);
    }
  }

  return 0;
}