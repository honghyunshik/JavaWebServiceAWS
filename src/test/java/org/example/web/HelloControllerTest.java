package org.example.web;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import static org.hamcrest.core.Is.is;


import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringRunner.class)        //테스트를 진행할 때 JUnit에 내장된 실행자 외에 다른 실행자(SpringRunner)를 실행시킵니다
//스프링 부트 테스트와 JUnit 사이에 연결자 역할을 한다
@WebMvcTest(controllers = HelloController.class)        //여러 스프링 테스트 어노테이션 중 Web(Spring MVC)에 집중할 수 있는 어노테이션
//@Controller, @ControllerAdvice 등 사용 가능, @Service, @Repository 등 사용 불가

public class HelloControllerTest {

    @Autowired      //스프링이 관리하는 빈을 주입받는다
    private MockMvc mvc;        //웹API를 테스트할때 사용. 스프링 MVC 테스트의 시작점이며, 이 클래스를 통해 HTTP GET, POST 등 API 테스트 가능

    @Test
    public void hello_return() throws Exception{

        String hello = "hello";

        mvc.perform(get("/hello"))      //MockMvc를 통해 /hello 주소로 HTTP GET 요청을 한다
                .andExpect(status().isOk())     // HTTP Header의 Status를 검증(200 or not)
                .andExpect(content().string(hello));        //응답 본문의 내용을 검증한다(hello가 맞는지)
    }

    @Test
    public void helloDto_return() throws Exception{

        String name = "hello";
        int amount = 1000;

        mvc.perform(get("/hello/dto")
                .param("name",name)
                .param("amount", String.valueOf(amount)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name",is(name)))
                .andExpect(jsonPath("$.amount",is(amount)));



    }

}
