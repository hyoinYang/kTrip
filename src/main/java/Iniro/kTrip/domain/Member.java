package Iniro.kTrip.domain;

import Iniro.kTrip.dto.MemberDto;
import jakarta.persistence.*;
import lombok.*;

@Entity(name = "Member")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Member {
    @Id
    @Column(name="mid")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int mid;

    @Column(length = 20)
    private String id;
    @Column(length = 20)
    private String password;

    @Column(length = 50, columnDefinition = "MEDIUMTEXT")
    private String email;
    @Column(length = 20)
    private String nickname;
    @Column(length = 20)
    private String name;

    @Column(name = "access_token", length=255)
    private String accessToken;
    @Column(name="refresh_token", length=255)
    private String refreshToken;
    @Column(length = 20)
    private String loginType;


    @Column(length=255)
    private String expiration;
    @Column(length=255)
    private String role;
    public void updatepassword(String new_password)
    {
        this.password=new_password;
    }


    // Oauth 구현할 때의 생성자.
    public Member(String userId, String nickname, String email,String type){
        this.id = userId;
        this.password = "PassWord";
        this.nickname = nickname;
        this.email = email;
        this.loginType = type;
    }
}
