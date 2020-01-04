#define RAPIDJSON_NO_SIZETYPEDEFINE

namespace rapidjson { typedef size_t SizeType; }
using namespace rapidjson;

#include "rapidjson/document.h"		// rapidjson's DOM-style API
#include "rapidjson/error/en.h"


#include <string.h>
#include <sstream>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <map>
#include <vector>
#include <thread>

#pragma comment(lib,"Ws2_32.lib")
#include <ws2tcpip.h>
#include <mswsock.h> // Need for SO_UPDATE_CONNECT_CONTEXT

#include "curses.h" 
#include "sph_shabal.h"
#include "mshabal.h"
#include "mshabal256.h"
#include "shabal_asm.h"
#include "InstructionSet.h"
#include "picohttpparser.h"

HANDLE hHeap;

bool exit_flag = false;
#ifdef __AVX2__
	char const *const version = "v0.1.7";
#else
	#ifdef __AVX__
		char const *const version = "v0.1.7";
	#else
		char const *const version = "v0.1.7";
	#endif
#endif 

unsigned long long startnonce = 0;
unsigned long nonces = 0;
unsigned int scoop = 0;
unsigned long long deadline = 0;
int network_quality = 100;
char signature[33];
char str_signature[65];
char oldSignature[33];
unsigned long long height = 0;
int st_height = 0; //here has one problem, when block is out of range.
unsigned long long baseTarget = 0;
unsigned long long targetDeadlineInfo = 0;			
unsigned long long my_target_deadline = MAXDWORD;	
volatile int stopThreads = 0;
char *pass = nullptr;						

std::string nodeaddr = "localhost";	
std::string nodeport = "8125";	

std::string ownerId = "3MhzFQAXQMsmtTmdkciLE3EJsgAQkzR4Sg";
std::string http_account = "";
std::string http_password = "";

std::string updateraddr = "localhost";
std::string updaterport = "8125";		

std::string infoaddr = "localhost";	
std::string infoport = "8125";		

std::string proxyport = "8125";		
std::string minername = "MinerName";
std::string accountkey = "Ackey";

char *p_minerPath = nullptr;		
size_t miner_mode = 0;				
size_t cache_size = 100000;			
size_t cache_size2 = 100000;		
std::vector<std::string> paths_dir; 		
FILE * fp_Log = nullptr;			
size_t send_interval = 100;			
size_t update_interval = 1000;		
short win_size_x = 80;
short win_size_y = 60;
bool use_debug = false;
bool enable_proxy = false;
bool use_wakeup = false;
bool use_log = true;			
bool use_boost = false;
bool show_winner = false;
unsigned long long POC2StartBlock = 0;
bool POC2 = false;
SYSTEMTIME cur_time;				//
unsigned long long total_size = 0;	//
WINDOW * win_main;
std::vector<std::thread> worker;

struct t_worker_progress{
	size_t Number;
	unsigned long long Reads_bytes;
	bool isAlive;
};

std::vector<t_worker_progress> worker_progress;
std::map <u_long, unsigned long long> satellite_size;

struct t_files{
	std::string Path;
	std::string Name;
	unsigned long long Size;// = 0;
	std::string Key;
	unsigned long long StartNonce;
	unsigned long long Nonces;
	unsigned long long Stagger;
	bool P2;
};

struct t_shares{
	std::string file_name;
	std::string account_id;// = 0;
	unsigned long long best;// = 0;
	unsigned long long nonce;// = 0;
};

std::vector<t_shares> shares;

struct t_best{
	std::string account_id;// = 0;
	unsigned long long best;// = 0;
	unsigned long long nonce;// = 0;
	unsigned long long DL;// = 0;
	unsigned long long targetDeadline;// = 0;
};

std::vector<t_best> bests;

struct t_session{
	SOCKET Socket;
	unsigned long long deadline;
	t_shares body;
};

std::vector<t_session> sessions;

#ifdef GPU_ON_C
struct t_gpu{
	size_t max_WorkGroupSize = 1;
	size_t use_gpu_platform = 0;
	size_t use_gpu_device = 0;
	cl_device_id *devices = nullptr;
	cl_uint num_devices = 0;
	cl_uint max_ComputeUnits = 1;
};
t_gpu gpu_devices;
#endif


CRITICAL_SECTION sessionsLock;
CRITICAL_SECTION bestsLock;	
CRITICAL_SECTION sharesLock;

// ========== HEADERS ==========
void ShowMemErrorExit(void);
void Log_init(void);
void Log(char const *const strLog);
void Log_server(char const *const strLog);
void Log_llu(unsigned long long const llu_num);
void Log_u(size_t const u_num);
int load_config(char const *const filename);
int xdigit(char const digit);
size_t xstr2strr(char *buf, size_t const bufsize, const char *const in);
void GetPass(char const *const p_strFolderPath);
size_t GetFiles(const std::string &str, std::vector <t_files> *p_files);
size_t Get_index_acc(const std::string& key);
void proxy_i(void);
void send_i(void);
void procscoop_m_4(unsigned long long const nonce, unsigned long long const n, char const *const data, size_t const acc, const std::string &file_name);
void procscoop_m256_8(unsigned long long const nonce, unsigned long long const n, char const *const data, size_t const acc, const std::string &file_name);
void procscoop_sph(const unsigned long long nonce, const unsigned long long n, char const *const data, const size_t acc, const std::string &file_name);
void procscoop_asm(const unsigned long long nonce, const unsigned long long n, char const *const data, const size_t acc, const std::string &file_name);
void work_i(const size_t local_num);
char* GetJSON(char const *const req);
void GetBlockInfo(unsigned const num_block);
void pollLocal(void);
void updater_i(void);
void hostname_to_ip(char const *const  in_addr, char* out_addr);
void GetCPUInfo(void);
int main(int argc, char **argv);