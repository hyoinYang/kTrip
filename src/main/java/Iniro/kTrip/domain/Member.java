package Iniro.kTrip.domain;

import jakarta.persistence.*;
import lombok.*;

@Entity(name = "Member")
@Data
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Member {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int mid;

    @Column(length = 20)
    private String id;
    @Column(length = 20)
    private String email;
    @Column(length = 20)
    private String password;
    @Column(length = 20)
    private String nickname;
    @Column(length = 20)
    private String name;

    @Column(length=255)
    private String access_token;
    @Column(length=255)
    private String refresh_token;
    @Column(length = 20)
    private String loginType;
}