/*
 * Copyright (C) 2002-2026 Free Software Foundation, Inc.
 *
 * This file is part of LIBTASN1.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libtasn1.h>

int
main (int argc, char **argv)
{
  int result = 0, len;
  asn1_node definitions = NULL, node1 = NULL;
  char errorDescription[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
  const char *choicefile = getenv ("ASN1CHOICE_OCSP");
  const char *datafile = getenv ("ASN1CHOICE_OCSP_DATA");
  FILE *fp;
  char data[1024];
  char data2[1024];
  int data_size = sizeof (data);

  if (!choicefile)
    choicefile = "pkix.asn";

  if (!datafile)
    datafile = "ocsp.der";

  /* Encode */
  result = asn1_parser2tree (choicefile, &definitions, errorDescription);
  if (result != ASN1_SUCCESS)
    {
      printf ("error in %d: %s\n", __LINE__, errorDescription);
      exit (1);
    }

  result = asn1_create_element (definitions, "PKIX1.ResponseData", &node1);
  if (result != ASN1_SUCCESS)
    {
      printf ("error in %d\n", __LINE__);
      exit (1);
    }

  fp = fopen (datafile, "rb");
  if (fp == NULL)
    {
      printf ("error in %d\n", __LINE__);
      exit (1);
    }
  data_size = fread (data, 1, sizeof (data), fp);
  fclose (fp);

  result = asn1_der_decoding (&node1, data, data_size, errorDescription);
  if (result != ASN1_SUCCESS)
    {
      printf ("error in %d: %s\n", __LINE__, errorDescription);
      exit (1);
    }

  len = sizeof (data2);
  result = asn1_der_coding (node1, "", data2, &len, errorDescription);
  if (result != ASN1_SUCCESS)
    {
      printf ("error in %d: %s\n", __LINE__, errorDescription);
      exit (1);
    }

  if (len != data_size)
    {
      printf ("length doesn't match (got: %d, should be: %d)\n", len,
	      data_size);
      exit (1);
    }

  if (memcmp (data, data2, len) != 0)
    {
      printf ("contents don't match\n");
      exit (1);
    }

  asn1_delete_structure (&node1);
  asn1_delete_structure (&definitions);

  return 0;
}
