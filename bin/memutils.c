/*
* pibs - Passive Identification of BackScatter
*
* Copyright (C) 2019 Gerard Wagener
* Copyright (C) 2019 CIRCL Computer Incident Response Center Luxembourg
* (SMILE gie).
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
#include "pibs.h"

//FIXME not generic enough if more segments are needed
int load_shmid_file(pibs_t* pibs)
{
    FILE* fp;
    if (pibs->shmid_file[0]) {
        fp = fopen(pibs->shmid_file,"r");
        if (fp) {
            //FIXME check file
            fscanf(fp, "%d", &pibs->shmid);
            return pibs->shmid;
        }
    } else {
        pibs->errno_pibs = ERR_NO_SHMID_FILE;
    }
    return -1;
}
int pibs_shmat(pibs_t* pibs)
{
    /* FIXME  init function needs to break up in two functions. One that
     *       initializes internal pibs structures as cli options etc
     *       a second one for describing the data itself, size of bin_table
     *       number of items etc.
     */
    if (pibs->data) {
        free(pibs->data);
        pibs->data = NULL;
    }
    if (pibs->data) {
        pibs->errno_pibs =  ERR_ATTACH_NOT_EMPTY;
        printf("TEST Data is not null\n");
        return -1;
    }
    if (!pibs->shmid_file[0]) {
        pibs->errno_pibs = ERR_NO_SHMID_FILE;
        return -1;
    }
    if (load_shmid_file(pibs) > 0) {
            pibs->data = shmat(pibs->shmid, NULL, SHM_RND);
        if ( (int) pibs->data == -1) {
            pibs->errno_copy = errno;
        } else {
            return 1;
        }
    }
    // Something did not work
    return -1;
}

int pibs_shmget(pibs_t* pibs)
{
    FILE* fp;
    pibs->shmid = shmget(IPC_PRIVATE, pibs->data_size, IPC_CREAT |  0600);
    if (pibs->shmid < 0) {
        pibs->errno_copy = errno;
    }

    if (pibs->shmid_file[0]){
            fp = fopen(pibs->shmid_file, "w");
            if (fp) {
                fprintf(fp,"%d",pibs->shmid);
                fclose(fp);
            }
            //TODO error handling
    }
    //TODO attach to it and bzero it
    //setup the tables
    return pibs->shmid;
}

