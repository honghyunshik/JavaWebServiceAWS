package org.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

//메인 클래스
//SpringBootApplication 어노테이션은 스프링 부트의 자동 설정, Bean 읽기와 생성을 자동으로 설정
//해당 어노테이션이 있는 위치부터 설정을 읽어가기 때문에 프로젝트 최상단에 위치해야 함
//내장 WAS를 실행한다(별도로 외부에 WAS(ex - Tomcat)를 두지 않고 내부에서 WAS를 실행하는 것) -> 스프링부트로 만들어진 JAR 파일로 실행
//내장 WAS를 사용하게 되면 언제 어디서나 같은 환경에서 스프링 부트를 배포할 수 있다(외부 WAS 버전을 일치시킬 필요가 없음)
@EnableJpaAuditing  //JPA Auditing 활성화
@SpringBootApplication
public class Application {
    public static void main(String[] args){
        SpringApplication.run(Application.class,args);
    }
}
