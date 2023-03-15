package org.example.domain.posts;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.example.domain.BaseTimeEntity;

import javax.persistence.*;

@Getter
@NoArgsConstructor      //기본 생성자 자동 추가
@Entity     //테이블과 링크될 클래스임을 나타낸다
//클래스의 카멜케이스 이름(ex - SalesManager.java) <-> 테이블의 언더스코어 네이밍(ex - sales_manager table) 매칭
//Entity 클래스에서는 Setter 메소드를 만들지 않는다. 생성자를 통해 값을 채우며, 값 변경이 필요할 경우 해당 이벤트에 맞는 public 메소드를 호출하여 변경.
public class Posts extends BaseTimeEntity {

    @Id     //해당 테이블의 PK 필드를 나타냄
    @GeneratedValue(strategy = GenerationType.IDENTITY)     //PK의 생성 규칙을 나타냄. IDENTITY는 기본키 생성을 DB에 위임
    private Long id;        //Entity의 PK는 Long 타입의 AUTO_increment를 권장함.

    @Column(length = 500,nullable = false)      //테이블의 칼럼을 나타내며, 선언하지 않아도 모두 테이블의 칼럼이 되지만
    //기본값 이외에 추가로 변경이 필요한 옵션이 있으면 사용한다
    //문자열의 경우 VARCHAR(255)가 기본값인데, 사이즈를 500으로 늘리려거나, 타입을 변경하는 등
    private String title;

    @Column(columnDefinition = "TEXT", nullable = false)
    private String content;

    private String author;

    @Builder        //해당 클래스의 빌더 패턴 클래스를 생성, 생성자 상단에 선언 시 생성자에 포함된 빌드만 빌더에 포함
    public Posts(String title, String content, String author){
        this.title = title;
        this.content = content;
        this.author = author;
    }

    public void update(String title, String content){
        this.title = title;
        this.content = content;
    }


}
