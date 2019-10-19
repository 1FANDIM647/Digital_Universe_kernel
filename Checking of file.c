#include <glib.h>
#include <string.h>

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>


char *string_from_file(char const *filename ){


 char *out;

 GError *e =NULL;

 GIOChannel *f=g_io_channel_new_file(filename , "r" , &e);
 if (!f) {

 	fprintf(stderr,  " mistake of opening file  " "%s\n", filename );
 	return NULL ;
 }

if (g_io_channel_read_to_end (f,&out, NULL,&e) !=G_IO_STATUS_NORMAL) {

 fprintf(stderr , " file '%s'has found , but while is reading we getting  the mistake .\n", filename);
 return NULL ;



}

return out ; 
}


ok_array *ok_array_new  (char *instring ,char const *delimiters ) {

  ok_array *out=malloc(sizeof (ok_array));
  *out=(ok_array){.base_string=instring};
  char *scratch= NULL ;
  char *txt=strock_r(instring,delimiters,&scratch);
  if (!txt) return NULL;
  while (txt) {

  out->elements = realoc(out->elements, sizeof(char*)*++(out->length));
  out->elements[out->length-1]=txt;
  txt=strock_r(NULL,delimiters,&scratch);



  }
  return out;

}

// Libereting  the  origin line , becasue stroke_r made it sick and  we do not  need  it more 

void ok_array_free(ok_array *ok_in){
     
     if(ok_in ==NULL) return;
     free(ok_in->base_string);
     free(ok_in->elements);
     free(ok_in);

}

#ifdef test_ok_array 
int main()
{
	 char *delimiters="'~!@#$%^&*()-_+={[]}|\\;:/",<>./?\n"";
	 ok_array *o= ok_array_new(strdup("Hello , reader.  This is text."),delimiters);

    assert(o->length==5);
    assert(!strcmp(o->elements[1],"reader"));
    assert(!strcmp(o->elements[4], "text"));
    ok_array_free(0);
    printf("OK.\n");

	
} 
#endif
