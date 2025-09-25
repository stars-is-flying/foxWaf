// build_rules.go
package main

import (
	"flag"
	"fmt"
	"os"
)

func build() {
	var forceRebuild bool
	flag.BoolVar(&forceRebuild, "force", false, "强制重新编译规则")
	flag.Parse()
	
	if forceRebuild {
		fmt.Println("强制重新编译规则...")
		os.Remove("rules.cache")
	}
	
	if err := CompileAndSaveRules(); err != nil {
		fmt.Printf("规则编译失败: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Println("规则编译完成！")
}