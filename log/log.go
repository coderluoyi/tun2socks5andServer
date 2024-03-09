package log

import (
	"fmt"
	"time"
)

func Info(format string, args ... any){
	fmt.Println("time=", time.Now(), " [Info] ", fmt.Sprintf(format, args))
}

func Warning(format string, args ... any){
	fmt.Println("time=", time.Now(), " [Warning] ", fmt.Sprintf(format, args))
}

func Error(format string, args ... any){
	fmt.Println("time=", time.Now(), " [Error] ", fmt.Sprintf(format, args))
}

func Debug(format string, args ... any){
	fmt.Println("time=", time.Now(), " [Debug] ", fmt.Sprintf(format, args))
}