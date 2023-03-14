package org.example.web.dto;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter     //선언된 모든 필드의 get 메소드를 생성해준다
@RequiredArgsConstructor       //선언된 모든 final 필드가 포함된 생성자를 선언해 준다. final이 없는 필드는 생성자에 포함 X
//name과 amount 필드로 구성된 생성자가 생성된다
public class HelloResponseDto {

    private final String name;
    private final int amount;
}
