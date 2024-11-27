#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_WORD_LENGTH 100
#define MAX_WORDS 1000


struct Device {
      char IP[50];
      char MAC[50];
      char date[50];
      char time[50];
      int safeFlag;
};
int numOfDev = 0;
int detectAttack = 0;
char *vic = "str";

int isStringInArr(struct Device devices[], int size,  char *string, char *string2) {
      
      int i = 0;
      char *strMatch = "string";
      char *strMAC1 = "string";
      while (i < size){
        strMatch = devices[i].IP; 
        strMAC1 = devices[i].MAC;
        int result = strcmp(string2,strMAC1);
       
        if(result == 0){
            i++; 
            int result2 = strcmp(strMatch,string);
            
            if(result2 != 0){
		vic = string;
//                printf("\n                ATTACK DETECTED      \n ");
//                printf("      ATTACKER IP: %s \n", strMatch);
//                printf("               MAC: %s \n", string2);
//                printf("        VICTIM IP: %s \n\n", string);
//              system("/sbin/iptables -A INPUT -m --mac-source 00:0F:EA:91:04:08 -j DROP");
                char cmd[100];
		sprintf(cmd, "sudo /sbin/iptables -A INPUT -s %s -j DROP", strMatch);
		system(cmd);
		detectAttack++;
                devices[i-1].safeFlag = 1;
                return 2;
            }
            return 0;
        }
        i++;     
      }
      return 1;
    }


int main() {
    
  FILE *outputFile;
  FILE *historyFile;

  char line[MAX_WORD_LENGTH * MAX_WORDS];
  char listOfDevices[MAX_WORDS][MAX_WORD_LENGTH];
  int y = 0;
  struct Device device1[500];

  char *str2 = "string";
  int ret = 0;
 
  outputFile = fopen("monitorOUT.txt","w");
 

  printf("\n               RUNNING APAD ...            \n"); 
  while(1){
//    FILE *file = fopen("/Users/Owner/Downloads/log2.txt", "r");   //this one demo normal log2.txt
  FILE *file = fopen("log.txt", "r");  
    outputFile = fopen("monitorOUT.txt","w");
    FILE *historyFile = fopen("monitorHistory.txt","w");
    

    //check if file is valid
    if (file == NULL) {
       perror("Error opening file");
       return 1; 
       // Exit the program with an error code
    }
    // Read and parse each line until the end of the file
    while (fgets(line, sizeof(line), file) != NULL) {
        char *token = strtok(line, " "); // Tokenize the line based on spaces
        char words[MAX_WORDS][MAX_WORD_LENGTH];
        int wordCount = 0;
        while (token != NULL) {

            // Array to store words
            if (wordCount < MAX_WORDS) {
                // Copy the token (word) into the array
                strncpy(words[wordCount], token, sizeof(words[wordCount]) - 1);
                words[wordCount][sizeof(words[wordCount]) - 1] = '\0'; // Null-terminate the word
                wordCount++;
            } else {
                fprintf(stderr, "Maximum word count reached. Ignoring additional words.\n");
                break;
            }            
            token = strtok(NULL, " ");
        }
        
        ret = isStringInArr(device1,numOfDev,words[4],words[7]);
        
        if (ret == 1){
          strcpy(device1[y].IP, words[4]);
          strcpy(device1[y].MAC, words[7]);
          strcpy(device1[y].date, words[0]);
          strcpy(device1[y].time, words[1]);
          printf("%s %s \n",words[0], words[1]);
          printf("Adding DEVICE [%d] , IP: %s , MAC: %s to your network ... \n\n",y+1,words[4],words[7]);
          numOfDev++;
          y++;
        }    
       
    }
    
    for (int i = 0; i < y; i++) {
        
        int sf = device1[i].safeFlag;
        if(sf>0){fprintf(historyFile,"ATTACK DETECTED!!! IP:%s MAC:%s - VICTIM IP: %s \n",device1[i].IP,device1[i].MAC,vic);}


        fprintf(outputFile,"%s %s %d \n",device1[i].IP,device1[i].MAC,sf);
        
        fprintf(historyFile,"DEVICE [%d] ADDED - DATE: %s TIME: %s IP: %s MAC: %s\n",
            i+1,device1[i].date,device1[i].time,device1[i].IP,device1[i].MAC);
    }
    fclose(historyFile);
    fclose(outputFile);
    sleep(1);

  }

  return 0; 
}
