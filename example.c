#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *usage_str = "USAGE:\n%s <filename>\n";

struct image {
	uint32_t h;
	uint32_t w;
	char * name; //some random meta info
	uint8_t *pixels;
};

uint8_t *read_file(const char *filename)
{
	uint8_t *buf;
	// open file
	FILE *f = fopen(filename, "rb");
	if (f == NULL) {
		puts("Could not open file");
		return NULL;
	}

	// determine size of file
	fseek(f, 0, SEEK_END);
	long f_size = ftell(f);
	fseek(f, 0 , SEEK_SET);

	// allocate memory
	buf = malloc(f_size);
	if (buf == NULL) {
		puts("Could not allocate memory");
		return NULL;
	}

	// read content
	fread(buf, 1, f_size, f);
	fclose(f);

	return buf;
}

int img_load(struct image *img, uint8_t *data)
{

	uint32_t h, w, name_len;
	char * name;
	uint8_t *pixels;
	int pos;

	/* Parse header:
	 *   +---+-----+-----+--------+----+------+
	 *   |IMG|hight|width|name_len|name|pixels|
	 *   +---+-----+-----+--------+----+------+
	 */

	// "IMG"
	if (data[0] != 'I' || data[1] != 'M' || data[2] != 'G') {
#ifdef DEBUG
		puts("no IMG");
#endif
		return 1;
	}

	pos = 3;

	// hight
	h = *((uint32_t *)(data + pos));
	pos += sizeof(uint32_t);

	// width
	w = *((uint32_t *)(data + pos));
	pos += sizeof(uint32_t);

	if (h * w == 0) {
		return 1;
	}


	// name_len
	name_len = *((uint32_t *)(data + pos));
	pos += sizeof(uint32_t);
#ifdef DEBUG
	printf("%d\n", (unsigned int)name_len);
#endif
	if (name_len != 0) {
	
		// name
		name = malloc(name_len+1);
		if (name == NULL) {
			return 1;
		}

		//strncpy(name, (char *)&data[pos], name_len);
		strcpy(name, (char *)&data[pos]);
		pos += name_len;
#ifdef DEBUG
		printf("%s\n", name);
#endif
	}
	// pixels
	pixels = malloc(h*w);
	if (pixels == NULL) {
		return 1;
	}
	memcpy(pixels, &data[pos], h*w);
	
	// populate struct
	img->h = h;
	img->w = w;
	img->name = name;
	img->pixels = pixels;
	
	return 0;
}

void img_destroy(struct image *img)
{
	if (img == NULL) {
		return;
	}
	img->h = 0;
	img->w = 0;
	if (img->name != NULL) {
		free(img->name);
		img->name = NULL;
	}
	if (img->pixels != NULL) {
		free(img->pixels);
		img->pixels = NULL;
	}
}

int main(int argc, char **argv)
{
	uint8_t *file_content = NULL;
	struct image img = {0};
	int retval;
	
	if (argc != 2) {
		printf(usage_str, argv[0]);
		return 1;
	}

	file_content = read_file(argv[1]);
	if (file_content == NULL) {
		return 1;
	}
	retval = img_load(&img, file_content);
	free(file_content);
	
	
	//...
	
	img_destroy(&img);
	return retval;
}
