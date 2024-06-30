package Iniro.kTrip.service;

import Iniro.kTrip.domain.Member;
import Iniro.kTrip.dto.MemberDto;
import Iniro.kTrip.jwt.JWTUtil;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import Iniro.kTrip.repository.MemberRepository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthService {

    private final MemberRepository memberRepository;
    private final JWTUtil jwtUtil;
    private final PasswordEncoder encoder;

    private MemberDto memberDto;

    @Transactional
    // 회원가입 서비스 코드
    public boolean signUp(Member member){
        Member isExist = memberRepository.findById(member.getId());
        if (Objects.isNull(isExist)){
            member.setPassword(encoder.encode(member.getPassword()));
            memberRepository.save(member);
            return true;
        }
        else{
            return false;
        }

    }

    @Transactional
    // 로그인 서비스 코드. 로그인 성공(회원 db에 존재하는 정보)하면 true
    public String login(Member member){
        ModelMapper modelMapper = new ModelMapper();

        String id = member.getId();
        Member requestMember = memberRepository.findById(id);
        String password = member.getPassword();

        if (Objects.isNull(requestMember)){
            System.out.println("존재하지 않는 ID입니다.");
            return null;
        }

        // 암호화된 password를 디코딩한 값과 password 값이 다르면 null 반환
        if (!(Objects.equals(password, requestMember.getPassword()))) {
            System.out.println("비밀번호가 일치하지 않습니다.");
            return null;
        }

        String accessToken = jwtUtil.createAccessToken("Authorization",member, 60000);
        return accessToken;
    }




}
