#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#define PORT 4444

volatile int admin_login = 0;
pid_t childpid;
int number_child = 0;
int arr_child[100];
int i,j;

void send_sig_to_child_oldest()
{	
	if ( 0 < number_child )
	{
		printf("in send sig oldest %d\n", number_child );
		kill(arr_child[number_child-1], SIGUSR2);
		number_child--;
		admin_login = 1;
	}
	
}

void add_child(int cpid)
{
	arr_child[number_child] = cpid;	
	number_child ++;
}
void signal_handler(int signo)
{
	/* child send signal to parrent  */
	if (SIGUSR1 == signo)
	{
		if( 0 == admin_login )	
		{
			send_sig_to_child_oldest();
		}
	}
	/* parrent send signal to child */
	else if ( SIGUSR2 == signo )
	{
		/* child */
		admin_login = 0;	
	}
	/*  child */
	else if (SIGCHLD == signo)
	{
		puts("jump to sig child");
		admin_login = 0;	
	}
}

int configable() 
{
	return (0 == admin_login);
}

const int NUM_INTERFACE = 2;

struct control{
	char interface[50], alias[50], mode[50];
};

struct lan{
	char interface[50], rule[50], proto[50], srcip[50], srcmac[50], mask[50];
};

struct list_ip{
	int size_white, size_black;
	char black[50][50],  white[50][50];
};

struct list_mac{
	int size_white, size_black;
	char black[50][50], white[50][50];
};

void init(struct control list_control[], struct lan list_lan[])
{
	char interface[50] = "eth";
	for (i = 1; i < NUM_INTERFACE; ++i)
	{
		interface[3] = '0' + i;
		interface[4] = NULL;
		strcpy(list_control[i].interface, interface);
		strcpy(list_control[i].alias, "GE1-GigE");
		strcpy(list_control[i].mode, "Disable");

		strcpy(list_lan[i].interface, interface);
		strcpy(list_lan[i].rule, "");
		strcpy(list_lan[i].proto, "");
		strcpy(list_lan[i].srcip, "");
		strcpy(list_lan[i].srcmac, "");
		strcpy(list_lan[i].mask, "");
	}
}

void show(struct control list[])
{
	printf("Interface Alias Filter Rule Mode\n");
	for (i = 1; i < NUM_INTERFACE; i++)
	{
		printf("%s\t", list[i].interface);
		printf("%s\t", list[i].alias);
		printf("%s\t", list[i].mode);
		printf("\n");
	}
}

int find_id(char interface[50])
{
	return (interface[strlen(interface) - 1] - '0');
}

void delete_lan(int id, struct lan list_lan[])
{
	char interface[50] = "eth";
	interface[3] = '0' + id;
	interface[4] = NULL;
	strcpy(list_lan[id].interface, interface);
	strcpy(list_lan[id].rule, "");
	strcpy(list_lan[id].proto, "");
	strcpy(list_lan[id].srcip, "");
	strcpy(list_lan[id].srcmac, "");
	strcpy(list_lan[id].mask, "");
}

void send_control(int Socket, struct control list_control[])
{
	for (i = 1; i < NUM_INTERFACE; i++)
	{
		send(Socket, list_control[i].interface, 50, 0);
		send(Socket, list_control[i].alias, 50, 0);
		send(Socket, list_control[i].mode, 50, 0);
	}
}

void send_rule(int Socket, struct lan _lan)
{
	for (i = 1; i < NUM_INTERFACE; i++)
	{
		send(Socket, _lan.interface, 50, 0);
		send(Socket, _lan.rule, 50, 0);
		send(Socket, _lan.proto, 50, 0);
		send(Socket, _lan.srcip, 50, 0);
		send(Socket, _lan.srcmac, 50, 0);
		send(Socket, _lan.mask, 50, 0);
	}
}

void update_rule(int Socket, struct lan list_lan[], struct control list_control[])
{
	char rule[50], interface[50];
	recv(Socket, rule, 50, 0);
	recv(Socket, interface, 50, 0);
	int id = find_id(interface);
	
	if (0 == strcmp(list_control[id].mode, "Disable"))
	{
		printf("Premiss Denied!\n");
		send(Socket, "Premiss Denied!", 50, 0);
		return;
	}
	send(Socket, "Update Success!", 50, 0);

	send(Socket, "Rule Name:\t", 50, 0);
	recv(Socket, list_lan[id].rule, 50, 0);
	send(Socket, "Protocol:\t", 50, 0);
	recv(Socket, list_lan[id].proto, 50, 0);
	send(Socket, "Source IP:\t", 50, 0);
	recv(Socket, list_lan[id].srcip, 50, 0);
	send(Socket, "Source MAC:\t", 50, 0);
	recv(Socket, list_lan[id].srcmac, 50, 0);
	send(Socket, "Mac mask:\t", 50, 0);
	recv(Socket, list_lan[id].mask, 50, 0);
	printf("Update Success!\n");
	send_rule(Socket, list_lan[id]);
}

void delete_rule(int Socket, struct lan list_lan[], struct control list_control[])
{
	char interface[50];
	recv(Socket, interface, 50, 0);
	int id = find_id(interface);
	if (0 == strcmp(list_control[id].mode, "Disable"))
	{
		send(Socket, "Premiss Denied!", 50, 0);
		return;
	}
	send(Socket, "Success!", 50, 0);
	delete_lan(id, list_lan);
}

struct control list_control[3];
struct lan list_lan[5];
struct list_ip ip_list;
struct list_mac mac_list;

void add_black_ip(char ip[50])
{
	for (i = 0; i < ip_list.size_black; i++)
	{
		if (0 == strcmp(ip, ip_list.black[i]))
			return;
	}
	
	for (i = 0; i < ip_list.size_white; i++)
	{
		if (0 != strcmp(ip, ip_list.white[i])) 
			continue;
		for (j = i + 1; j < ip_list.size_white; j++)
		{
			strcpy(ip_list.white[j-1], ip_list.white[j]);
		}
		ip_list.size_white--;
	}
	strcpy(ip_list.black[ip_list.size_black], ip);

	ip_list.size_black++;

}

void add_white_ip(char ip[50])
{
	for (i = 0; i < ip_list.size_white; i++)
	{
		if (0 == strcmp(ip, ip_list.white[i])) 
			return;
	}
	
	for (i = 0; i < ip_list.size_black; i++)
	{
		if (0 != strcmp(ip, ip_list.black[i])) 
			continue;
		for (j = i + 1; j < ip_list.size_black; j++)
		{
			strcpy(ip_list.black[j-1], ip_list.black[j]);
		}
		ip_list.size_black--;
	}
	strcpy(ip_list.white[ip_list.size_white], ip);
	ip_list.size_white++;
}

void add_black_mac(char mac[50])
{
	for (i = 0; i < mac_list.size_black; i++)
	{
		if (0 == strcmp(mac, mac_list.black[i])) 
			return;
	}
	for (i = 0; i < mac_list.size_white; i++)
	{
		if (0 != strcmp(mac, mac_list.white[i])) 
			continue;
		for( j = i + 1; j < mac_list.size_white; j++)
		{
			strcpy(mac_list.white[j-1], mac_list.white[j]);
		}
		mac_list.size_white--;
	}
	strcpy(mac_list.black[mac_list.size_black], mac);
	mac_list.size_black++;
}

void add_white_mac(char mac[50])
{
	for(i = 0; i < mac_list.size_white; i++)
	{
		if (0 == strcmp(mac, mac_list.white[i]))
			return;
	}
	
	for(i = 0; i < mac_list.size_black; i++)
	{
		if (0 !=strcmp(mac, mac_list.black[i])) 
			continue;
		for( int j = i + 1; j < mac_list.size_black; j++)
		{
			strcpy(mac_list.black[j-1], mac_list.black[j]);
		}
		mac_list.size_black--;
	}
	strcpy(mac_list.white[mac_list.size_white], mac);
	mac_list.size_white++;
}
int true_ip(char ip[])
{
        char *p, ip_tmp[50];
        int tmp;
        strcpy(ip_tmp, ip);
        p = strtok(ip_tmp, ".");
        while (NULL!= p)
	{
                tmp = atoi(p);
                if (tmp < 0 || tmp >255)
		{
			printf("IP not true!\n");
			return 0;
		}
                p = strtok(NULL, ".");
        }
        return 1;
}


int main()
{
	init(list_control, list_lan);

	int sockfd, ret;
	struct sockaddr_in serverAddr;

	int newSocket;
	struct sockaddr_in newAddr;

	socklen_t addr_size;

	char buffer[1024];

	signal(SIGUSR1, signal_handler);
	signal(SIGUSR2, signal_handler);
	signal(SIGCHLD, signal_handler);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
	{
		printf("[-]Error in connection.\n");
		exit(1);
	}
	printf("[+]Server Socket is created.\n");

	memset(&serverAddr, '\0', sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(PORT);
	serverAddr.sin_addr.s_addr = INADDR_ANY;//inet_addr("127.0.0.1");

	ret = bind(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
	if (ret < 0)
	{
		printf("[-]Error in binding.\n");
		exit(1);
	}
	printf("[+]Bind to port %d\n", 4444);


	if (0 == listen(sockfd, 10))
	{
		printf("[+]Listening....\n");
	}
	else
	{
		printf("[-]Error in binding.\n");
	}


	while (1)
	{
		newSocket = accept(sockfd, (struct sockaddr*)&newAddr, &addr_size);
		if (newSocket < 0)
		{
			exit(0);
		}

		printf("Connection accepted from %s:%d\n", inet_ntoa(newAddr.sin_addr), ntohs(newAddr.sin_port));
		
		childpid = fork();
		if ( childpid > 0) 
		{
			add_child(childpid);
		}
		
		else if (0 == childpid)
		{
			admin_login = 1;
			close(sockfd);
	                char user[50], pass[50];
			memset(user, '\0',50);
			memset(pass, '\0',50);

	   		recv(newSocket,user,50,0);
                        recv(newSocket,pass,50,0);
			printf("%s\n",user);
			printf("%s\n",pass);
			
			while (0 != strcmp(user,"Dasan")!=0||strcmp(pass,"123456"))
			{
			    send(newSocket,"Login Again!",50,0);
            	            recv(newSocket,user,50,0);
               		    recv(newSocket,pass,50,0);
			}
			relogin:printf("admin_login = %d\n", admin_login);
			        kill(getppid(), SIGUSR1);
				usleep(100000);
				if (configable())
					puts("ok");
			
				else 
				{
					puts("admin busy");
					goto relogin;
				}
	
			printf("Admin logged in to Server\n");
                        send(newSocket,"Wellcome Admin!",50,0);
			send_control(newSocket, list_control);
			while (1)
			{
				recv(newSocket, buffer, 1024, 0);
				if (0 == strcmp(buffer, ":exit") == 0)
				{
					printf("Disconnected from %s:%d\n", 
					       inet_ntoa(newAddr.sin_addr), ntohs(newAddr.sin_port));
					kill(getppid(), SIGCHLD);
					sleep(1);
					return 0;	
					break;
				}
				
				else if (0 == strcmp(buffer, "set"))
				{
					char interface[50], mode[50];
					recv(newSocket, mode, 50, 0);
					recv(newSocket, interface, 50, 0);
					int id = find_id(interface);
					strcpy(list_control[id].mode, mode);
					send(newSocket, "Success!", 50, 0);
					send_control(newSocket,list_control);
					printf("Server set %s %s: Success!\n", mode, interface);
				}
				
				else if (0 == strcmp(buffer, "block"))
				{
					recv(newSocket, buffer, 1024, 0);
					if (0 == strcmp(buffer,"ip"))
					{
						char ip[50], command[50], phu[50];
						recv(newSocket,ip,50,0);
						printf("Success Block IP %s\n",ip);
						if (!true_ip(ip))
						{
							send(newSocket, "Wrong IP!", 50, 0);
							continue;
						}
						send(newSocket, "Block IP Success!", 50, 0);	
						strcpy(command, "iptables -I INPUT 1 -s ");
						strcpy(phu, " -j DROP");
						strcat(command,ip);
						strcat(command,phu);
                                		system(command);
						add_black_ip(ip);
						char str[5];
						sprintf(str, "%d",ip_list.size_black);
						send(newSocket,str, 10, 0);
						
						for (i=0; i < ip_list.size_black; i++)
						{
							send(newSocket, ip_list.black[i], 50, 0);
						} 
					}
					
					else if (0 == strcmp(buffer,"rangeIP"))
					{
						char ip[50], command[80],phu[50];
						recv(newSocket,ip,50,0);
						printf("Succes Block RangeIP %s\n",ip);
						send(newSocket,"Block RangeIP Success!",50,0);
						strcpy(command,"sudo iptables -I INPUT 1 -m iprange --src-range ");
						strcpy(phu, " -j DROP");
						strcat(command, ip);
						strcat(command, phu);
						system(command);
						add_black_ip(ip);
						char str[5];
						sprintf(str, "%d",ip_list.size_black);
						send(newSocket,str, 10, 0);
						for (i=0; i < ip_list.size_black; i++)
						{
							send(newSocket, ip_list.black[i], 50, 0);
						} 
					}
					
					else if(0 == strcmp(buffer,"all"))
					{
						char command[80];
						printf("Succes Block All");
						send(newSocket,"Block All  Success!",50,0);
						strcpy(command,"sudo iptables -I INPUT 1 -j DROP");
						system(command);
					}
					
					else if (0 == strcmp(buffer,"mac"))
					{
						char mac[50], command[80], phu[50];
						recv(newSocket,mac,50,0);
						printf("Success Block IP %s\n",mac);
 						send(newSocket, "Block MAC Success!", 50, 0);
						strcpy(command, "iptables -I INPUT 1 -m mac --mac-source ");
						strcpy(phu, " -j DROP");
						strcat(command,mac);
						strcat(command,phu);
                                		system(command);
						add_black_mac(mac);
						char str[5];
						sprintf(str,"%d",mac_list.size_black);
						send(newSocket,str,10,0);
						
						for (i=0; i < mac_list.size_black; i++)
						{
							send(newSocket, mac_list.black[i], 50, 0);
						}
				 
					}
                                }
				
				else if ( 0 == strcmp(buffer, "allow"))
				{
					recv(newSocket,buffer,1024,0);
					if (0 == strcmp(buffer,"ip"))
					{
						char ip[50], command[50], phu[50];
						recv(newSocket,ip,50,0);
						printf("Success Allow IP %s\n",ip);
						if (!true_ip(ip))
						{
							send(newSocket, "Wrong IP!", 50, 0);
							continue;
						}
						send(newSocket, "Allow IP Success!", 50, 0);
						strcpy(command, "iptables -I INPUT 1 -s ");
						strcpy(phu, " -j ACCEPT");
						strcat(command,ip);
						strcat(command,phu);
                                		system(command);
						add_white_ip(ip);
						char str[5];
						sprintf(str,"%d",ip_list.size_white);
						send(newSocket,str, 10, 0);
						for (i=0; i < ip_list.size_white; i++)
						{
							send(newSocket, ip_list.white[i], 50, 0);
						} 
					}
					
					else if (0 == strcmp(buffer,"rangeIP"))
					{
						char ip[50], command[80], phu[50];
						recv(newSocket,ip,50,0);
						printf("Success Allow rangeIP %s\n",ip);
						if (!true_ip(ip))
						{
							send(newSocket, "Wrong IP!", 50, 0);
							continue;
						}
						send(newSocket, "Allow rangeIP Success!", 50, 0);
						strcpy(command, "sudo iptables -I INPUT 1 -m iprange --src-range ");
						strcpy(phu, " -j ACCEPT");
						strcat(command,ip);
						strcat(command,phu);
                                		system(command);
						add_white_ip(ip);
						char str[5];
						sprintf(str,"%d",ip_list.size_white);
						send(newSocket,str, 10, 0);
						for (i=0; i < ip_list.size_white; i++)
						{
							send(newSocket, ip_list.white[i], 50, 0);
						} 
					}
					
					else if (0 == strcmp(buffer,"all"))
					{
						char  command[50];
						printf("Success Allow All");
						send(newSocket, "Allow All Success!", 50, 0);
						strcpy(command, "sudo iptables -I INPUT 1 -j ACCEPT");
                                		system(command);
					}
					
					else if (0  == strcmp(buffer,"mac"))
					{
						char mac[50], command[80], phu[50];
						recv(newSocket,mac,50,0);
						printf("Success Allow MAC %s\n",mac);
						send(newSocket, "Allow MAC Success!",50,0);
						strcpy(command, "iptables -I INPUT 1 -m mac --mac-source ");
						strcpy(phu, " -j ACCEPT");
						strcat(command,mac);
						strcat(command,phu);
                                		system(command);
						add_white_mac(mac);
						char str[5];
						sprintf(str,"%d",mac_list.size_white);
						send(newSocket,str,10,0);
						for (i=0; i < mac_list.size_white; i++)
						{
							send(newSocket, mac_list.white[i], 50, 0);
						}
					}
                                }

				else if (0 == strcmp(buffer, "update"))
				{
					update_rule(newSocket, list_lan, list_control);
				}
				
				else if (0 == strcmp(buffer, "delete"))
				{
					delete_rule(newSocket, list_lan, list_control);
				}
				
				else
				{
					printf("Client ( %s ) : %s\n", inet_ntoa(newAddr.sin_addr),buffer);
					send(newSocket, buffer, strlen(buffer), 0);
					bzero(buffer, sizeof(buffer));
				}
			}
		}
	}

	close(newSocket);
	return 0;
}
