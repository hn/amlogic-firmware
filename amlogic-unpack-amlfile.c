/*
 * amlogic-unpack-amlfile.c, V1.00
 *
 * Unpack files from Amlogic's AML firmware archive (AVOS update file)
 *
 * Sent in and placed in the Public Domain by an anonymous contributor
 *
 */

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>

/**
Reverse engineering of Picopix firmware
AVOS amlogic image.
Extract partitions and DATA files directory.
*/

struct mi_partition_header
{
  char checksum[4];
  short int rsv;
  short int partitions;
};

struct mi_partition_table
{
  unsigned int length;
  unsigned int checksum;
  unsigned int offset;
  unsigned int index;
  char info[0x3c];
};

/**
 structure describing header of a DATAFS00 partition
*/
struct mi_datafs_header
{
  unsigned long long tag;
  unsigned long long rsv;
  unsigned short v1;
  unsigned short v2;
  unsigned int tablesize;
  unsigned int datastart;
  unsigned int datasize;
  unsigned int namestart;
  unsigned int namesize;
};

/**
 structure describing an entry in list of files/directories
*/
struct mi_file_entry
{
  char name[256];
  unsigned int start;
  unsigned int length;
};

struct aml_header
{
  unsigned int tag;
  unsigned int v1;
  unsigned int v2;
  unsigned int tblstart;
  unsigned int tblcount;
  unsigned int astart;
  unsigned int acount;
  unsigned int chksm;
  unsigned int bcount;
  unsigned long long rsv;
  char timestampstr[16];
};

struct aml_chunk_desc
{
  unsigned int start;
  unsigned int length;
  unsigned int address;
  unsigned int blocksize;
  unsigned int xor_checksum;
};

inline char toh(unsigned char i)
{
  return ( i < 10) ? ('0' + i) : ('a' + (i-10));
}

void hdump(char buffer)
{
     printf("%c%c", toh(( (unsigned char) buffer)/16), toh(((unsigned char) buffer)%16));
}


/**
 * 'B' for big endian
 * 'L' for little endian
 */
void hexdump(char endianness, int n, char* buffer)
{
  int i=0;
  if (endianness == 'L')
    {
      for (i=0; i<n; i++) {
	hdump(buffer[i]);
      }
    }
  else
    {
      for (i=n-1; i>=0; i--) {
	hdump(buffer[i]);
      }
    }
}

unsigned int xor_checksum(FILE *fp, int start, int length, unsigned int test)
{
  char buffer[65536];
  int read = 0;
  int readen = 0;
  int toread=0;
  unsigned int checksum=0;
  fseek(fp, start, SEEK_SET);
  while (readen < length )
    {
      read=fread(buffer, 1, (length - readen > sizeof(buffer)) ? sizeof(buffer) : length-readen,fp);
      if ( read <= 0 )
	{
	  break;
	}
      {
	unsigned int i=0;
	for (i=0;i<read/4;i++)
	  {
	    checksum = checksum ^  *((unsigned int*) &buffer[i*4]) ;
	    /*
	    if ( checksum == test )
	      {
		printf( "************** test ******** %u %u %u %x\n", readen,read,i,checksum);
	      }
	    */
	  }
	/* no pad...
	if ( read % 4 != 0)
	  {
	    printf( "** checksum pad %u %u %u %x %x\n",read, read % 4,i,test,checksum);
	  }
	switch (read % 4)
	  {
	  case 3:
	    checksum = checksum ^ ( *((unsigned int*) &buffer[i*4]) & 0xFFFFFF);
	    break;
	  case 2:
	    checksum = checksum ^ ( *((unsigned int*) &buffer[i*4]) & 0xFFFF);
	    break;
	  case 1:
	    checksum = checksum ^ ( *((unsigned int*) &buffer[i*4]) & 0xFF);
	    break;
	  }
	*/
      }
      readen += read;
      /*
      if ( readen < length )
	{
	  printf( "** read another block %u/%u %x %x\n", readen, length, test,checksum);
	}
      */
    }
  return checksum;
}

/**
 * returns filesize using fseek, keep current position in file 
 **/
int file_size(FILE *fp)
{
    long current=ftell(fp);
    long filesize=0;
    fseek(fp, 0L, SEEK_END);
    filesize=ftell(fp);
    fseek(fp,current,SEEK_SET);
    return filesize;
}

/**
 * given a FILE* f already openned at a specific read position
 * will create a new file named filename a copy length bytes
 * from f into this new file.
 */
void copy_file_part_to_filename(FILE* f, char* filename, int length)
{
  FILE* outfile;
  char buffer[1024];
  int contentread=0;
  int nread=0;

  outfile=fopen(filename,"ab");
  if (outfile != NULL)
    {
      while (( contentread < length ) && ( ! feof(f)) && ( ! ferror(f)))
	{
	  int remaining=length - contentread;
	  nread=fread(buffer,1, remaining >  sizeof(buffer) ? sizeof(buffer) : remaining ,f);
	  if ( nread > 0)
	    {
	      if (fwrite(buffer,1,nread,outfile) == nread )
		{
		  contentread+=nread;
		}
	      else
		{
		  printf("*** %s %u %u short write\n", filename, contentread, length);
		}
	    }
	}
      fclose(outfile);
      clearerr(f);
      if (contentread != length )
	{
	  printf("** %s %u %u\n", filename, contentread, length);
	}
    }
  else
    {
      printf("** %s %u creation failed\n", filename, length);
    }
}

void analyze_partition(FILE* f,
		       unsigned int offset,
		       unsigned int length,
		       unsigned short partition)
{
  int i=0;
  int filestart=0;
  int max_entries=0x1a6;
  int filetablestart=0x33c;
  struct mi_file_entry mi_fentry[max_entries];
  unsigned long long tag;

  fseek(f, offset, SEEK_SET);
  fread(&tag,1,sizeof(tag),f);
  if ( tag == 0x3030534641544144l ) // DATAFS00
    {
      char contentdir[128];
      struct mi_datafs_header datafs_header;
      sprintf(contentdir,"data.%u",partition);
      fseek(f, offset, SEEK_SET);
      fread(&datafs_header,1,sizeof(datafs_header),f);
      filetablestart=offset+0x200;
      max_entries=datafs_header.tablesize / 0x20; // each each is size 0x20 before name start
      // need to read some information here to get max_entries and filetablestart
      fseek(f, filetablestart, SEEK_SET);
      {
	int count= max_entries;
	for (i=0; i < count;i++)
	  {
	    char entry[32];
	    int n=0;
	    fread(entry,sizeof(entry),1,f);
	    for (n=0; n<8; n++)
	      {
		hexdump('L',4,&entry[n*4]);
		putchar(' ');
	      }
	    mi_fentry[i].start=*((unsigned int *) (&entry[2*4]));
	    mi_fentry[i].length=*((unsigned int *) (&entry[3*4]));
	    printf("\n");
	  }
      }
      {
	char buffer[256];
	char * ptr;
	int length=0;
	int counter=0;
	int cut=0;
	int filetextcount=0;
	while (counter < max_entries)
	  {
	    fread(buffer,sizeof(buffer)-1,1,f);
	    buffer[sizeof(buffer) -1]=0;
	    ptr=buffer;
	    do
	      {
		length=strlen(ptr);
		if ((ptr + length) < (buffer + sizeof(buffer) -1))
		  {
		    strncpy(mi_fentry[counter].name + cut,ptr,length);
		    mi_fentry[counter].name[cut+length]=0;
		    if (cut == 0)
		      {
			printf("%u) %s\n",counter,ptr);
		      }
		    else
		      {
			printf("%s\n",ptr);
			cut=0;
		      }	
		    counter++;
		    ptr += length + 1;
		    filetextcount += length + 1;
		  }
		else
		  {
		    strncpy(mi_fentry[counter].name,ptr,length);
		    mi_fentry[counter].name[length]=0;
		    printf("%u) %s",counter,ptr);
		    cut=length;
		    filetextcount += length;
		    break;
		  }
		
	      } while ( (length >=0) && ( counter < max_entries));
	    filestart=filetablestart + max_entries * 32 +  filetextcount;
	  }
      }
      printf("filestart %u\n", filestart);
      if ( filestart - offset != datafs_header.datastart )
	{
	  printf("** filestart -offset != datastart %x %x\n", filestart - offset, datafs_header.datastart);
	}
      if (mkdir(contentdir, 0777) == 0)
	{
	  for (i=0; i< max_entries;i++)
	    {
	      char filename[300];
	      printf("%u) %s %u %u\n", i, mi_fentry[i].name, mi_fentry[i].start, mi_fentry[i].length);
	      snprintf(filename,300,"%s/%s", contentdir,mi_fentry[i].name);
	      if ( fseek(f, mi_fentry[i].start + filestart, SEEK_SET) == 0)
		{
		  copy_file_part_to_filename(f,filename,mi_fentry[i].length);
		}
	      else
		{
		  printf("** %s %u %u\n", mi_fentry[i].name, mi_fentry[i].length, mi_fentry[i].start);
		}
	    }  
	  // create a 'remaining' file
	  {
	    long current=ftell(f);
	    if (current < length )
	      {
		copy_file_part_to_filename(f,"remaining",length-current);
	      }
	  }
	}
      else
	{
	  printf("** content directory %s already exists please move it away\n", contentdir);
	}
    }
  else if ( (tag & 0xFFFFFFFFl) == 0x414d4c20l )
    {
      char contentfile[128];
      sprintf(contentfile,"mla.partition.%u",partition);
      printf("'MLA ' partition tag %xl to %s\n", tag, contentfile);
      fseek(f, offset, SEEK_SET);
      {
	long current=ftell(f);
	if (current == offset )
	  {
	    copy_file_part_to_filename(f,contentfile,length);
	  }
      }
      fseek(f, offset, SEEK_SET);
      {
	struct aml_header header;
	int chunk=0;
	fread(&header,1,sizeof(header),f);
	fseek(f, offset + 0x64, SEEK_SET);
	if (header.tblcount < 0x100) 
	{
	  struct aml_chunk_desc chunk_desc[header.tblcount];
	  fread(chunk_desc,sizeof(struct aml_chunk_desc),header.tblcount,f);
	  for (chunk=0; chunk < header.tblcount;chunk++)
	    {
	      unsigned int chunk_length=chunk_desc[chunk].length & 0xFFFFFF;
	      unsigned int checksum;
	      if (chunk_length > 0)
		{
		  checksum=xor_checksum(f,offset+chunk_desc[chunk].start, chunk_length,chunk_desc[chunk].xor_checksum);
		  if ( checksum != chunk_desc[chunk].xor_checksum )
		    {
		      printf("** chunk %u checksum mismatch %x %x\n", chunk, chunk_desc[chunk].xor_checksum, checksum);
		    }
		}
	      else
		{
		  checksum=0;
		}
	      printf("[%8x +%8u =%8x[ \t [%6x +%8u =%6x[ \t %8x \t %8x %8x \n", 
		     chunk_desc[chunk].address, chunk_desc[chunk].blocksize, chunk_desc[chunk].address + chunk_desc[chunk].blocksize,
		     chunk_desc[chunk].start, chunk_length, chunk_desc[chunk].start+ chunk_length,
		     chunk_desc[chunk].length & 0xFF000000, chunk_desc[chunk].xor_checksum, checksum );
	    }
	}
	else
	  {
	    printf("** too many chunks %u\n", header.tblcount);
	  }
      }
    }
  else 
    {
      char contentfile[128];
      sprintf(contentfile,"partition.%u",partition);

      printf("dumping unrecognized partition tag %xl to %s\n", tag, contentfile);
      fseek(f, offset, SEEK_SET);
      {
	long current=ftell(f);
	if (current == offset )
	  {
	    copy_file_part_to_filename(f,contentfile,length);
	  }
      }
    }

}

void print_partition_table(
			   struct mi_partition_header *mi_ph,
			   struct mi_partition_table *mi_ptable
			   )
{
  int index=0;
  for (index=0;index <mi_ph->partitions;index++)
    {
      struct mi_partition_table *mi_this_table=&mi_ptable[index];
      printf("%u) [%x+%u ->%x[ (%u)\n", index, mi_this_table->offset,mi_this_table->length,mi_this_table->offset + mi_this_table->length, mi_this_table->index);
    }
}

int main(int argc, char** argv)
{
  if (argc >0)
    {
      char* file = argv[1];
      int max_partitions=4;
      struct mi_partition_header mi_ph;
      struct mi_partition_table mi_ptable[max_partitions];

      int i=0;
      FILE *f = fopen(file,"rb");
      {
	char header[4];
	if ( fread(header,1,4,f) == 4)
	  {
	    printf("%c%c\n",header[0],header[1]);
	    if (( header[1] != 'I' ) || ( header[0] != 'M' ))
	      {
		printf("INVALID TAG , expected 'IM'00 (little endian) \n");
		fclose(f);
		return -1;
	      }
	  }
	else
	  {
	    printf("FILE TOO SHORT , expected 'IM'00 (little endian) \n");
	    fclose(f);
	    return -1;
	  }
      }
      // partition table
      {
	if (! fread(&mi_ph,1,sizeof(mi_ph),f) == sizeof(mi_ph))
	  {
	    printf("FILE TOO SHORT , expected partition header of length %u \n", sizeof(mi_ph));
	    fclose(f);
	    return -1;
	  }
	if (mi_ph.partitions < max_partitions )
	  {
	    fread(mi_ptable,mi_ph.partitions,sizeof(struct mi_partition_table),f);
	  }
	else
	  {
	    printf("Too many partitions %u/%u \n", mi_ph.partitions, max_partitions);
	    fclose(f);
	    return -1;
	  }	
      }
      print_partition_table(&mi_ph,mi_ptable);
      {
	int index=0;
	for (index=0;index<mi_ph.partitions;index++)
	  {
	    analyze_partition(f,mi_ptable[index].offset,mi_ptable[index].length,mi_ptable[index].index);
	  }
      }
      fclose(f);
    }
}
