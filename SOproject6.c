#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

#define MAX_PATH_LENGTH 1024
#define MAX_ENTRIES 1000

struct EntryMetadata {
    char name[MAX_PATH_LENGTH];
    time_t lastModified;
    mode_t permissions;
    off_t size;
};

//Functie pentru verificarea drepturilor lipsa si executia script-ului de analiza sintactica
void checkPermissionsAndExecuteScript(const char *filePath, const char *isolatedSpaceDir, int pipe_fd) {
    //Verificam drepturile lipsa ale fisierului
    struct stat metadata;
    if (stat(filePath, &metadata) == -1) {
        perror("Eroare la obtinerea metadatelor");
        exit(EXIT_FAILURE);
    }

    //Verificam daca toate drepturile sunt lipsa
    if ((metadata.st_mode & S_IRWXU) == 0 && (metadata.st_mode & S_IRWXG) == 0 && (metadata.st_mode & S_IRWXO) == 0) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("Eroare la crearea procesului copil");
            exit(EXIT_FAILURE);
        } else if (pid == 0) {
            //Suntem in procesul copil, executam script-ul de analiza sintactica
            close(pipe_fd); //Inchidem capatul de scriere al pipe-ului in procesul fiu
            dup2(pipe_fd, STDOUT_FILENO); //Redirectionam stdout catre pipe
            execl("/bin/bash", "/bin/bash", "-c", "./verify_for_malicious.sh", filePath, NULL);
            perror("Eroare la executarea scriptului");
            exit(EXIT_FAILURE);
        } else {
            //Suntem in procesul parinte, asteptam terminarea procesului copil
            close(pipe_fd); //Inchidem capatul de citire al pipe-ului in procesul parinte
            wait(NULL); //Asteptam terminarea procesului copil
        }
    }
}

//Functie pentru actualizarea snapshot-ului unui director si verificarea drepturilor lipsa pentru fiecare fisier
void updateSnapshotAndCheckPermissions(const char *dirPath, const char *isolatedSpaceDir, int *corruptedFilesCount) {
    struct EntryMetadata snapshot[MAX_ENTRIES];
    int entryCount = 0;

    DIR *dir = opendir(dirPath);
    if (dir == NULL) {
        perror("Eroare la deschiderea directorului");
        exit(EXIT_FAILURE);
    }

    int pipe_fds[2]; //Pipe pentru comunicarea intre procesul fiu si parinte
    if (pipe(pipe_fds) == -1) {
        perror("Eroare la crearea pipe-ului");
        exit(EXIT_FAILURE);
    }
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            //Construim calea absoluta catre fisier/director
            char fullPath[MAX_PATH_LENGTH];
            snprintf(fullPath, sizeof(fullPath), "%s/%s", dirPath, entry->d_name);

            //Verificam drepturile lipsa si executam script-ul de analiza sintactica pentru fiecare fisier
            checkPermissionsAndExecuteScript(fullPath, isolatedSpaceDir, pipe_fds[1]);

            //Citim rezultatul din pipe
            char result[50];
            close(pipe_fds[1]); //Inchidem capatul de scriere al pipe-ului in procesul fiu
            read(pipe_fds[0], result, sizeof(result));

            if (strcmp(result, "SAFE") != 0) {
                //Fisierul este suspect, trebuie mutat in directorul izolat
                printf("Fisierul suspect \"%s\" va fi mutat in directorul izolat.\n", fullPath);
                (*corruptedFilesCount)++;
                //Implementeaza mutarea fisierului in directorul izolat
                //Comentat pentru a evita efectuarea efectiva a mutarii
                //Implementarea depinde de cerintele specifice si de sistemul de operare
            }

            //Actualizam snapshot-ul doar daca fisierul este considerat sigur
            if (strcmp(result, "SAFE") == 0) {
                // Obtinem metadatele fisierului/directorului
                struct stat metadata;
                if (stat(fullPath, &metadata) == -1) {
                    perror("Eroare la obținerea metadatelor");
                    continue;
                }

                //Actualizam snapshot-ul
                struct EntryMetadata entryMetadata;
                strcpy(entryMetadata.name, entry->d_name);
                entryMetadata.lastModified = metadata.st_mtime;
                entryMetadata.permissions = metadata.st_mode;
                entryMetadata.size = metadata.st_size;

                //Adaugam metadatele in snapshot
                if (entryCount < MAX_ENTRIES) {
                    snapshot[entryCount] = entryMetadata;
                    entryCount++;
                } else {
                    printf("Atingere limita maxima de intrari. Nu se pot adauga mai multe.\n");
                    break;
                }
            }
        }
    }
    closedir(dir);

    //Afisam metadatele snapshot-ului pentru director
    printf("Snapshot-ul pentru directorul %s:\n", dirPath);
    for (int i = 0; i < entryCount; i++) {
        printf("Nume: %s, Ultima modificare: %s, Permisiuni: %o, Dimensiune: %ld bytes\n",
               snapshot[i].name,
               ctime(&snapshot[i].lastModified),
               snapshot[i].permissions & (S_IRWXU | S_IRWXG | S_IRWXO),
               snapshot[i].size);
    }
}

int main(int argc, char *argv[]) {
    //Verificam daca exista suficiente argumente in linia de comanda
    if (argc < 3 || argc > 13) {
        printf("Utilizare: %s [-s] [-o izolated_space_dir] director1 director2 ... (maxim 10 directoare)\n", argv[0]);
        return EXIT_FAILURE;
    }

    //Variabile pentru directorul de izolare si numarul de directoare
    char *isolatedSpaceDir = NULL;
    int numDirs = argc - 1;
    int corruptedFilesCount = 0;

    //Parcurgem argumentele pentru a identifica optiunile -s si -o
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0) {
            //Argumentul urmator indica directorul de izolare
            isolatedSpaceDir = argv[i + 1];
            numDirs -= 2;
            argv += 2; //Avansam argumentele pentru a ignora optiunile -s si -o
            break;
        } else if (strcmp(argv[i], "-o") == 0) {
            //Argumentul urmator indica directorul de izolare
            isolatedSpaceDir = argv[i + 1];
            numDirs -= 2;
            argv += 2; //Avansam argumentele pentru a ignora optiunile -s si -o
            break;
        }
    }

    //Cream un proces copil pentru fiecare director
    for (int i = 1; i <= numDirs; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("Eroare la crearea procesului copil");
            exit(EXIT_FAILURE);
        } else if (pid == 0) {
            //Suntem in procesul copil, actualizam snapshot-ul pentru directorul specificat si verificam drepturile lipsa pentru fiecare fisier
            updateSnapshotAndCheckPermissions(argv[i], isolatedSpaceDir, &corruptedFilesCount);
            exit(EXIT_SUCCESS);
        }
    }

    //Suntem in procesul parinte, asteptam terminarea fiecarui proces copil
    int status;
    pid_t child_pid;
    while ((child_pid = wait(&status)) != -1) {
        printf("Procesul cu PID-ul %d s-a incheiat cu codul %d\n", child_pid, WEXITSTATUS(status));
    }

    printf("Numarul total de fisiere corupte gasite: %d\n", corruptedFilesCount);

    return EXIT_SUCCESS;
}
