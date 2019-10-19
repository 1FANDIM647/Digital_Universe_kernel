#include <stdio.h>
#define LEN 100 

int creating_file_txt_for_reading_and_writting( ) {

 char str[LEN];.

 FILE *file_ptr;

 file_ptr = fopen("new_file.txt"  , "r+a")

 // r is  read  ,  w is write   ,  a is  adding  the  text  in  the our file , r+ 

  if (file_ptr != NULL) {
  	printf(" File : new is  created seccessufully   \n");
    while (fgets(str ,LEN  , file_ptr  )); // we get data  drom the file 
    fprintf(stdout , "%s\n" , str ) ; 
    printf("Reading is over "); 

    }  
  else 
  {
  	fprintf(stderr ,"File dosen't create s\n");

  	return 1 ; 
  }

}