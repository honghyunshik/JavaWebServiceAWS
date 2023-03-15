package org.example.web.domain.posts;

import org.example.domain.posts.Posts;
import org.example.domain.posts.PostsRepository;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringRunner.class)
@SpringBootTest     //H2데이터베이스를 자동으로 실행
public class PostsRepositoryTest {

    @Autowired
    PostsRepository postsRepository;

    @After      //JUnit에서 단위 테스트가 끝날 때마다 수행되는 메소드를 지정. 테스트 수행할 때 테스트 간 데이터 침법을 막기 위해 사용한다.
    public void cleanUp(){
        postsRepository.deleteAll();
    }


    @Test
    public void get_text(){

        //given
        String title = "테스트 게시글";
        String content = "테스트 본문";

        //테이블에 insert/update 쿼리를 실행한다. id값이 있다면 update, 없다면 insert 쿼리가 실행된다
        postsRepository.save(Posts.builder()
                .content(content)
                .title(title)
                .author("hshong0907@gmail.com")
                .build());

        //when
        List<Posts> postList = postsRepository.findAll();       //테이블 post의 모든 데이터를 조회한다.

        //then
        Posts posts = postList.get(0);
        assertThat(posts.getTitle()).isEqualTo(title);
        assertThat(posts.getContent()).isEqualTo(content);

    }

    @Test
    public void baseTimeEntity_check() throws Exception{

        //given
        LocalDateTime now = LocalDateTime.of(2023,3,15,0,0);
        postsRepository.save(Posts.builder()
                        .title("title")
                        .content("content")
                        .author("author")
                        .build());

        //when
        List<Posts> postsList = postsRepository.findAll();

        //then
        Posts posts = postsList.get(0);

        System.out.println(">>>>>>>>>> createDate=" +posts.getCreateDate()+", modifiedDate="+posts.getModifiedDate());
        assertThat(posts.getCreateDate()).isAfter(now);
        assertThat(posts.getModifiedDate()).isAfter(now);
    }




}
