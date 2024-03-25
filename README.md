Step 1: Save all files off into a seperate folder

Step 2: Perform an Open Folder in VS Code

Step 3: Install all dependencies required to run main

go mod download github.com/golang-jwt/jwt/v5
go mod download github.com/mattn/go-sqlite3

Step 4: Save gradebot to folder: (Note the program will return a score of 30/65 if gradebot is executed outside of the folder of the database as the program saves the db to the current working dir)

Step 5: navigate to the directory of the folder in command prompt and type the command "gradebot.exe project2"

-Testing Suite

Step 6: With main running type the command "go test -cover" to run cover against main_test

note: may need to install package via terminal "go get golang.org/x/tools/cmd/cover"
