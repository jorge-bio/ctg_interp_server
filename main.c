#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <dlfcn.h>
#include "jsmn.h" 
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define VERSION 1
#define BUFSIZE 1000000 //8192 //5242880 //5MB input limit
#define URISIZE 2048 //CHECK RFC FOR MAX URI SIZE
#define MAX_COMMAND_LENGTH 64
#define MAX_URI_LENGTH MAX_COMMAND_LENGTH+10
#define ERROR      42
#define LOG        44
#define FORBIDDEN 403
#define NOTFOUND  404
#define JSMN_PARENT_LINKS //JSMN is much faster with parent links enabled

#define METHOD_GET  1
#define METHOD_POST 2

#define BRANCH_PUBLIC  1
#define BRANCH_CTG  1

//define extensions supported for static files
struct {
	char *ext;
	char *filetype;
} extensions [] = {
	{"gif", "image/gif" },  
	{"jpg", "image/jpg" }, 
	{"jpeg","image/jpeg"},
	{"png", "image/png" },  
	{"ico", "image/ico" },  
	{"zip", "image/zip" },  
	{"gz",  "image/gz"  },  
	{"tar", "image/tar" },  
	{"htm", "text/html" },  
	{"html","text/html" },  
	{0,0} };
    

//Check URI characters
char checkChar(char ch_char){
    //uppercase / lowercase /number / _
    if( (ch_char>= 'A' && ch_char <= 'Z') ||
        (ch_char>= 'a' && ch_char <= 'z') ||
        (ch_char>= '0' && ch_char <= '9') ||
        ch_char == '_' || ch_char == '.' )  {
        return(ch_char);
    } else {
        return('\0');
    }
    
}

//Get branch and command from URI
int parseURI(char *URI, int *branch, char *command){
    char *str_branch;
    char *str_command;
    char tmp_uri[MAX_URI_LENGTH+1];
    char *stat;
    int cont;
    int error;
    
    error=0;
    //create a working copy of the original URI
    strncpy(tmp_uri,URI+1,MAX_URI_LENGTH);
    tmp_uri[MAX_URI_LENGTH]='\0';
    
    
    
    //extract branch from uri
    str_branch=strtok_r(tmp_uri,"/", &stat);
    if(strncmp(str_branch, "CTG",4)==0){
        *branch=BRANCH_CTG;
    } else if (strncmp(str_branch, "public",7)==0) {
        *branch=BRANCH_PUBLIC;
    } else {
        *branch=0;
        error=1;
    }

    *command='\0';
    if(!error) {
        //extract command from uri
        str_command=strtok_r(NULL,"/", &stat);
        cont=0;
        while(*(str_command+cont)!='\0' && cont< MAX_COMMAND_LENGTH) {
            
            *(command+cont)=checkChar(*(str_command+cont));
            
            if(*(command+cont)=='\0'){            
                break;
            }
            cont++;
        }
        //make sure command is ended properly
        *(command+cont)='\0';
    }
    
    return(error);
}    

//Simple function to log server access and errors
void logger(int type, char *s1, char *s2, int socket_fd)
{
	int fd ;
	char logbuffer[BUFSIZE*2];

	switch (type) {
	case ERROR: (void)sprintf(logbuffer,"ERROR: %s:%s Errno=%d exiting pid=%d",s1, s2, errno,getpid()); 
		break;
	case FORBIDDEN: 
		(void)write(socket_fd, "HTTP/1.1 403 Forbidden\nContent-Length: 185\nConnection: close\nContent-Type: text/html\n\n<html><head>\n<title>403 Forbidden</title>\n</head><body>\n<h1>Forbidden</h1>\nThe requested URL, file type or operation is not allowed on server.\n</body></html>\n",271);
		(void)sprintf(logbuffer,"FORBIDDEN: %s:%s",s1, s2); 
		break;
	case NOTFOUND: 
		(void)write(socket_fd, "HTTP/1.1 404 Not Found\nContent-Length: 136\nConnection: close\nContent-Type: text/html\n\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\nThe requested URL was not found on this server.\n</body></html>\n",224);
		(void)sprintf(logbuffer,"NOT FOUND: %s:%s",s1, s2); 
		break;
	case LOG: (void)sprintf(logbuffer," INFO: %s:%s:%d",s1, s2,socket_fd); break;
	}	
	/* No checks here, nothing can be done with a failure anyway */
	if((fd = open("server.log", O_CREAT| O_WRONLY | O_APPEND,0644)) >= 0) {
		(void)write(fd,logbuffer,strlen(logbuffer)); 
		(void)write(fd,"\n",1);      
		(void)close(fd);
	}
	if(type == ERROR || type == NOTFOUND || type == FORBIDDEN) exit(3);
}


//GET method for static files in public folder
void process_get(int fd,char URI[],int hit){
    char * fstr;
    long ret, buflen,i, len;
    int file_fd;
    static char buffer[BUFSIZE+1]; 
	/* work out the file type and check we support it */
	buflen=strlen(URI);
	fstr = (char *)0;
    char file_path[1024];
    
	for(i=0;extensions[i].ext != 0;i++) {
		len = strlen(extensions[i].ext);
		if( !strncmp(&URI[buflen-len], extensions[i].ext, len)) {
			fstr =extensions[i].filetype;
			break;
		}
	}

	//Check file extension
	if(fstr == 0) logger(FORBIDDEN,"file extension type not supported",URI,fd);

    //Read static file
    sprintf(file_path,"public/%s",URI);
	if(( file_fd = open(&file_path,O_RDONLY)) == -1) {  /* open the file for reading */
		logger(NOTFOUND, "failed to open file",&URI,fd);
	}
	logger(LOG,"SEND",&URI,hit);
	len = (long)lseek(file_fd, (off_t)0, SEEK_END); /* lseek to the file end to find the length */
	      (void)lseek(file_fd, (off_t)0, SEEK_SET); /* lseek back to the file start ready for reading */
          (void)sprintf(buffer,"HTTP/1.1 200 OK\nServer: ctg_interp_server/%d.0\nContent-Length: %ld\nConnection: close\nContent-Type: %s\n\n", VERSION, len, fstr); /* Header + a blank line */
	logger(LOG,"Header",buffer,hit);
	(void)write(fd,buffer,strlen(buffer));

	/* send file in 8KB block - last block may be smaller */
	while (	(ret = read(file_fd, buffer, BUFSIZE)) > 0 ) {
		(void)write(fd,buffer,ret);
	}
    
}

//POST method handle
void process_post(int fd,char command[],char message[],int hit){
    char * fstr;
    long ret, buflen,i, len;
    int file_fd;
    static char buffer[BUFSIZE+1]; 
    jsmn_parser p;
    int r;
    size_t tokcount = 300000;
    double signal[300000];
    jsmntok_t *tok;    
    char output[BUFSIZE+1];
    char c_type[100];
    int count,idx;
    char *p_token;    
    int id;
    int c_signal;
    int signal_len;
    char out_filename[255];
    
    void *handle;
    void (*plot_ctg)(double *,int, int, char *,char *);
    int paper_scale,error;
    char *plot;
    
    //initialize JSON parser

    jsmn_init(&p);
    
    //Allocate tokens	
    tok = malloc(sizeof(*tok) * tokcount);
	if (tok == NULL) {
		fprintf(stderr, "malloc(): errno=%d\n", errno);
		return 3;
	}
	
	signal_len=0;
    
    //Parse JSON according to command
	if(!strncmp(command,"plot_fhr",strlen("plot_fhr"))){
        r = jsmn_parse(&p, message, strlen(message), tok, tokcount);
        //strcpy(output,"HELLO WORLD POST"); 
        //dump(message, tok, p.toknext, 0);
        if(tok->size>0){
            count=1;
            
            while((tok+count)->start>0){
                
                //get id field 
                p_token=strndup(message+(tok+count)->start,(tok+count)->end-(tok+count)->start);
                                
                if(strncmp(p_token,"id",3)==0){
                    
                    count=count+1;
                    free(p_token);
                    
                    p_token=strndup(message+(tok+count)->start,(tok+count)->end-(tok+count)->start);
                    id=strtol(p_token,NULL,10);
                }
                free(p_token);

                
                //Get paperscale field
                p_token=strndup(message+(tok+count)->start,(tok+count)->end-(tok+count)->start);
                                
                if(strncmp(p_token,"paperscale",11)==0){
                    
                    count=count+1;
                    free(p_token);
                    
                    p_token=strndup(message+(tok+count)->start,(tok+count)->end-(tok+count)->start);
                    paper_scale=strtol(p_token,NULL,10);
                }
                free(p_token);
                
                
                //Read signal array
                p_token=strndup(message+(tok+count)->start,(tok+count)->end-(tok+count)->start);
                if(strncmp(p_token,"signal",7)==0){
                    count=count+1;
                    signal_len=(tok+count)->size;
                    //signal key                    
                    for(c_signal=0;c_signal<signal_len;c_signal++){
                        free(p_token);
                        p_token=strndup(message+(tok+count+c_signal+1)->start,(tok+count+c_signal+1)->end-(tok+count+c_signal+1)->start);
                       signal[c_signal]=strtod(p_token,NULL);
                       
                    }
                    
                    
                }
                free(p_token);
                
                count=count+(tok+count)->size+1;
                
                    
            }
            
            
            //Load SO library for CTG interpretation
            handle = dlopen ("./libcardiac_bio.so", RTLD_LAZY);
            {
                if (!handle) {
                    fprintf (stderr, "%s\n", dlerror());
                }
            }
            dlerror();    /* Clear any existing error */
            
            
            *(void **) (&plot_ctg)= dlsym(handle, "plot_ctg");

            if ((error = dlerror()) != NULL)  {
                fprintf (stderr, "%s\n", error);
                exit(1);
            }
            
            //Temp filename
            sprintf(out_filename,"out/%d",hit);
            //Process command using SO library                        
            (*plot_ctg)(signal,signal_len, paper_scale, plot,out_filename); //char *fecg, int s_length, int paper_scale, char *plot)
            dlclose(handle);
            
            //Return generaten tmp file
            
            sprintf(c_type,"image/png");
            
            if(( file_fd = open(out_filename,O_RDONLY)) == -1) {  /* open the file for reading */
                logger(NOTFOUND, "Error processing data",&command,fd);
            }
            logger(LOG,"SEND",&command,hit);
            len = (long)lseek(file_fd, (off_t)0, SEEK_END); /* lseek to the file end to find the length */
            (void)lseek(file_fd, (off_t)0, SEEK_SET); /* lseek back to the file start ready for reading */
            (void)sprintf(buffer,"HTTP/1.1 200 OK\nServer: ctg_interp_server/%d.0\nContent-Length: %ld\nConnection: close\nContent-Type: %s\n\n", VERSION, len, c_type); /* Header + a blank line */
            logger(LOG,"Header",buffer,hit);
            (void)write(fd,buffer,strlen(buffer));

            /* send file in 8KB block - last block may be smaller */
            while (	(ret = read(file_fd, buffer, BUFSIZE)) > 0 ) {
                (void)write(fd,buffer,ret);
            }
            
            
            
            
        }
        
    } else {
        sprintf(c_type,"json");
        strcpy(output,"{}");

        fstr = (char *)0;
        logger(LOG,"SEND",command,hit);
        len = strlen(output);
        (void)sprintf(buffer,"HTTP/1.1 200 OK\nServer: ctg_interp_server/%d.0\nContent-Length: %ld\nConnection: close\nContent-Type: %s\n\n", VERSION, len,c_type); /* Header + a blank line */
        logger(LOG,"Header",buffer,hit);
        (void)write(fd,buffer,strlen(buffer));

        /* send file in 8KB block - last block may be smaller */
        //while (	(ret = read(file_fd, buffer, BUFSIZE)) > 0 ) {
            (void)write(fd,output,ret);
        //}
                
    }
    
    
	
    
}

/* Child process web server */
void web(int fd, int hit)
{
	int j, file_fd, buflen, URI_idx, method,error;
	long i, ret, len;
	char * fstr;
	static char buffer[BUFSIZE+1]; /* static so zero filled */
    static char URI[URISIZE+1]; // CHECK MAX URI SIZE
    char *message;
    char *header;
    char command[MAX_COMMAND_LENGTH+1];
    int branch;
    //(void)write(fd, "HTTP/1.1 100 Continue\n\r",23);
    //sleep(1);
    sleep(1);
	ret =read(fd,buffer,BUFSIZE); 	/* read Web request in one go */
    printf("%s",buffer);
	if(ret == 0 || ret == -1) {	/* read failure stop now */
		logger(FORBIDDEN,"failed to read browser request","",fd);
	}
	if(ret > 0 && ret < BUFSIZE)	/* return code is valid chars */
		buffer[ret]=0;		/* terminate the buffer */
	else buffer[0]=0;
	//for(i=0;i<ret;i++)	/* remove CF and LF characters */
	//	if(buffer[i] == '\r' || buffer[i] == '\n')
	//		buffer[i]='*';
	//logger(LOG,"request",buffer,hit);
    
	if( strncmp(buffer,"GET ",4) && strncmp(buffer,"get ",4) && strncmp(buffer,"post ",5)  && strncmp(buffer,"POST ",5) ) {
		logger(FORBIDDEN,"Method not supported",buffer,fd);        
	}
	
	if(!strncmp(buffer,"GET ",4) && strncmp(buffer,"get ",4)){
        URI_idx=4;
        method=METHOD_GET;
    } else if(!strncmp(buffer,"POST ",5) && strncmp(buffer,"post ",5)){
        URI_idx=5;
        method=METHOD_POST;
    }
    
    //Extract URI
	i=URI_idx;
	while(i<BUFSIZE && buffer[i]!='\n' && buffer[i]!=' '){
        URI[i-URI_idx]=buffer[i];
        i++;
    }
    URI[i]='\0';
    for(j=0;j<i-URI_idx;j++) 	/* check for illegal parent directory use .. */
		if(URI[j] == '.' && URI[j+1] == '.') {
			logger(FORBIDDEN,"Parent directory (..) path names not supported",URI,fd);
		}
	if( !strncmp(URI,"/\0",2)){ /* convert no filename to index file in public branch*/
		(void)strcpy(URI,"/public/index.html");
    }

    //TODO: Check content-type and content-length
    //URI /branch/command
    error=parseURI(URI, &branch, &command);
    
    
    if(!error){
        //Find message content
        message=(const char *)strstr(buffer,"\r\n\r\n");
        
        if(message!=NULL){
            message=message+4;
            //split header and content
            *(message-1)='\0';
            *(message-2)='\0';
            header=buffer;
        }
        
        if(strstr(header,"Expect: 100-continue\r\n")!=NULL){
            //Client is waiting for confirmation before sendind additional data
            (void)write(fd, "HTTP/1.1 100 Continue\r\n",23);            
            sleep(1); //TODO find alternative way to wait            
            ret =read(fd,buffer,BUFSIZE); 	/* read Web request in one go */            
            message=buffer;
            
        }
        
        if(method==METHOD_GET && branch==BRANCH_PUBLIC){
            process_get(fd, command, hit);
        } else if(method==METHOD_POST){
            process_post(fd, command, message,hit);
        }
    } else {
        logger(NOTFOUND, "Wrong request",&URI,fd);
    }
    
	
	sleep(1);	/* allow socket to drain before signalling the socket is closed */
	close(fd);
	exit(1);
}


/* Main loop */
int main(int argc, char **argv)
{
	int i, port, pid, listenfd, socketfd, hit;
	socklen_t length;
	static struct sockaddr_in cli_addr; /* static = initialised to zeros */
	static struct sockaddr_in serv_addr; /* static = initialised to zeros */

	if( argc < 3  || argc > 3 || !strcmp(argv[1], "-?") ) {
		(void)printf("hint: ctg_interp_server Port-Number Top-Directory\t\tversion %d\n\n"
	"\tExample: ctg_interp_server 8181 /var/opt/ctg_interp &\n\n",VERSION);
		exit(0);
	}
	if( !strncmp(argv[2],"/"   ,2 ) || !strncmp(argv[2],"/etc", 5 ) ||
	    !strncmp(argv[2],"/bin",5 ) || !strncmp(argv[2],"/lib", 5 ) ||
	    !strncmp(argv[2],"/tmp",5 ) || !strncmp(argv[2],"/usr", 5 ) ||
	    !strncmp(argv[2],"/dev",5 ) || !strncmp(argv[2],"/sbin",6) ){
		(void)printf("ERROR: Bad top directory %s, see ctg_interp_server -?\n",argv[2]);
		exit(3);
	}
	if(chdir(argv[2]) == -1){ 
		(void)printf("ERROR: Can't Change to directory %s\n",argv[2]);
		exit(4);
	}
	/* Become deamon + unstopable and no zombies children (= no wait()) */
	if(fork() != 0)
		return 0; /* parent returns OK to shell */
	(void)signal(SIGCLD, SIG_IGN); /* ignore child death */
	(void)signal(SIGHUP, SIG_IGN); /* ignore terminal hangups */
	//for(i=0;i<32;i++)
	//	(void)close(i);		/* close open files */
	(void)setpgrp();		/* break away from process group */
	logger(LOG,"ctg_interp_server starting",argv[1],getpid());
	/* setup the network socket */
	if((listenfd = socket(AF_INET, SOCK_STREAM,0)) <0)
		logger(ERROR, "system call","socket",0);
	port = atoi(argv[1]);
	if(port < 0 || port >60000)
		logger(ERROR,"Invalid port number (try 1->60000)",argv[1],0);
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(port);
	if(bind(listenfd, (struct sockaddr *)&serv_addr,sizeof(serv_addr)) <0)
		logger(ERROR,"system call","bind",0);
	if( listen(listenfd,64) <0)
		logger(ERROR,"system call","listen",0);
	for(hit=1; ;hit++) {
		length = sizeof(cli_addr);
		if((socketfd = accept(listenfd, (struct sockaddr *)&cli_addr, &length)) < 0){
			logger(ERROR,"system call","accept",0);
        }
        
		if((pid = fork()) < 0) {
			logger(ERROR,"system call","fork",0);
		}
		
		else {
            
            //Process single request
        //    web(socketfd,hit); //Single request web server
            
			//Process parallel requests 
			if(pid == 0) { 	/* child */
				(void)close(listenfd);
				web(socketfd,hit); /* never returns */
			} else { 	/* parent */
				(void)close(socketfd);
			}
		}
	}
}
