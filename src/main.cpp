#include <cstring>
#include <iostream>
#include <seccomp.h>
#include <sstream>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace std;

// global variables
const int BUFFER_SIZE = 1024;
const int READ_END = 0;
const int WRITE_END = 1;
const int NUM_SYSCALLS = 330;

/*  Convenience function to make a pair of pipes  */
void make_pipe_pair(int *pair1, int *pair2) {
  if (pipe(pair1) == -1 || pipe(pair2) == -1) {
    cerr << "couldn't create pipe";
    exit(EXIT_FAILURE);
  }
}

/*  Convenience function to close a pair of file descriptors  */
void close_pair(const int rfd, const int wfd) {
  if (close(rfd) == -1 || close(wfd) == -1) {
    cerr << "couldn't close file";
    exit(EXIT_FAILURE);
  }
}

/*  Main child process function  */
void child_func(const int wpipe, const auto idx) {
  // child
  long long int ret = -1;

  auto arch = seccomp_arch_native();
  auto *name = seccomp_syscall_resolve_num_arch(arch, idx);

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

  // things currently break horribly if  CLONE, FORK or VFORK are called and the
  // call succeeds guess it should be straight forward to kill the forks
  // if (idx == SYS_clone) { exit(0); }
  // if (idx == SYS_fork) { exit(0); }
  // if (idx == SYS_vfork) { exit(0); }
  ret = syscall(idx, 0, 0, 0);

  // check both EPERM and EACCES - LXC returns EACCES and Docker EPERM
  std::string sStatus;
  if ((ret == EPERM) || (ret == EACCES)) {
    // cerr << "blocked" << endl;
    sStatus = "filtered";
  } else {
    // cerr << "allowed" << endl;
    sStatus = "allowed";
  }

  char writeMsg[BUFFER_SIZE];
  sprintf(writeMsg, "%u|%s|%s|%s|%d", idx, name, sStatus.c_str(),
          strerror(errno), errno);
  if (write(wpipe, writeMsg, strlen(writeMsg) + 1) == -1) {
    exit(EXIT_FAILURE);
  }

  /*  Close file descriptors and exit  */
  close(wpipe);
  exit(0);
}

int Usage(char *ProgramName) {
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

int main(int argc, char *argv[]) {

  int arg;
  bool bFiltered = false;
  bool bAllowed = false;
  bool bUnknownParam = false;

  if (argc > 3) {
    return Usage(argv[0]);
  }

  if (argc > 1) {
    for (arg = 1; arg < argc; arg++) {
      switch (argv[arg][0]) {

      case L'-':
      case L'/':
        switch (argv[arg][1]) {
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

  if (bUnknownParam) {
    return Usage(argv[0]);
  }

  if ((!bFiltered) && (!bAllowed)) {
    // means no params passed. Assume default of printing both
    bFiltered = true;
    bAllowed = true;
  }

  int ptoc_fd[NUM_SYSCALLS][2]; /*  Parent to child pipes    */
  int ctop_fd[NUM_SYSCALLS][2]; /*  Child to parent pipes    */
  pid_t children[NUM_SYSCALLS]; /*  Process IDs of children  */

  char readMsg[BUFFER_SIZE];

  /*  Create pipe pairs and fork children  */
  for (auto i = 0; i < NUM_SYSCALLS; ++i) {
    make_pipe_pair(ptoc_fd[i], ctop_fd[i]);

    if ((children[i] = fork()) == -1) {
      cerr << "error calling fork()";
      return EXIT_FAILURE;
    } else if (children[i] == 0) {
      close_pair(ctop_fd[i][0], ptoc_fd[i][1]);
      child_func(ctop_fd[i][1], i + 1);
      return EXIT_SUCCESS;
    } else {
      close_pair(ptoc_fd[i][0], ctop_fd[i][1]);
    }
  }

  /*  Loop through each child  */
  for (auto i = 0; i < NUM_SYSCALLS; ++i) {
    ssize_t num_read;
    if ((num_read = read(ctop_fd[i][0], readMsg, sizeof(readMsg))) == -1) {
      return EXIT_FAILURE;
    } else if (num_read == 0) {
      // cout << "Pipe from child " << i +1 << " closed." << endl;
    } else {

      std::string sReadMsg(readMsg);

      if ((bFiltered) && (bAllowed)) {
        cout << sReadMsg << endl;
      } else {
        if (bFiltered) {
          if (sReadMsg.find("|filtered|") != std::string::npos) {
            cout << sReadMsg << endl;
          }
        }
        if (bAllowed) {
          if (sReadMsg.find("|allowed|") != std::string::npos) {
            cout << sReadMsg << endl;
          }
        }
      }
    }
  }

  /*  Clean up and harvest dead children  */
  for (auto i = 0; i < NUM_SYSCALLS; ++i) {
    if (waitpid(children[i], NULL, 0) == -1) {
      return EXIT_FAILURE;
    }
    close_pair(ptoc_fd[i][1], ctop_fd[i][0]);
  }

  return 0;
}