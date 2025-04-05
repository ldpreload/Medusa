<p align="center">
	<i><u>Paralyze resistance with persistence.</i></u>
</p>
<p align="center">
  <img src="https://files.catbox.moe/q78mg1.png">
</p>

# &lceil;**Description**&rceil;
Medusa is a powerful, stealthy, versatile, and, modular rootkit designed to give attackers complete control over Linux systems. Medusa is compiled and ready to be executed as a small ELF executable file, which no means extra building or configuration requirements! Medusa is larger than a few hundred kilobytes in size. Once installed, the rootkit sets up a dynamic linker that modifies the way applications are loaded and executed on the system. At this point the Medusa hooks a plethora of API system calls, library functions and signal handlers to achieve imbreakable and uninterceptable persistence. Medusa intercepts a plethoa of system calls made by all applications on the Medusa infected machine.. Hooking these system calls allows a Medusa to control and modify the behavior when system call is made. For example, with `stat()` family calls, a user can specify what information should be returned when those calls are made, or make changes to the permissions of files and directories. With `access()`, the user can control who has permission to what areas of the system. With `write()`, `read()`, `open()`, and their derivatives, Medusa can control what files and directories are accessed by the system, and what data is written to them. Truncate and `chmod()` / `chown()` allows for control over how files and directories are manipulated. Pututxline, updwtmp, and pututline are used for managing user logins and account information.

# &lceil;**Features**&rceil;
- **PAM Backdoor**
&rarr; Hook libpam authentication system calls for persisting with a hidden root user
- **Process Hiding**
&rarr; 				Hooks rootkit can intercept the 'kill' function to prevent the user from terminating the rootkit process. By hiding itself from the system, the rootkit can remain undetected and achieve persistence on the system.
- **File Hiding**
&rarr; 				Hooks 'stat' and 'readdir' to hide files and directories.
- **Network Hiding**
&rarr; 				Hooks the 'getaddrinfo' function to filter out addresses of remote hosts that it wants to hide. By using these techniques, the rootkit can effectively hide network activity from the user and other programs.
- **Anti-Debugging**
&rarr; 				Also Hooks 'kill' system call can be intercepted to prevent the debugger from sending signals to the rootkit process. By evading debugging, the rootkit can make it more difficult for security researchers to discover and analyze its behavior.
- **Auth Logging**
&rarr; 				Hooks `pam_prompt()`, `pam_vprompt` and `pam_syslog` to log all successful authentications locally, or    remotely via SSH to Medusa home directory
- **Execution Logging**
&rarr; 				Hooks `syslog()` and `pam_syslog` to log all successful authentications locally, or    remotely via SSH to Medusa home directory

# **Building And Deployment**

Change the settings you want in **src/config.c** this includes your username and password that will be used to access the backdoor deployed by Medusa. 

**Default Backdoor Credentials:**
**Username**: adm1n
**Password**: asdfasdf

```ssh
make
```

The executable in **bin/rkload** is the deployable rootkit.

**Connect via SSH to backdoor:**
```ssh
ssh adm1n@infected-host.com
```
