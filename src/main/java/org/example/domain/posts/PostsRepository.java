package org.example.domain.posts;


import org.springframework.data.jpa.repository.JpaRepository;

//MyBatis의 Dao라고 불리는 DB Layer 접근자이며, interface로 생성한다. JpaRepository<Entity 클래스, PK타입>을 상속하면 기본적인 CRUD 메소드가 자동으로 생성된다.
//Entity 클래스와 Entity Repository는 함께 위치한다.
public interface PostsRepository extends JpaRepository<Posts,Long> {


}
