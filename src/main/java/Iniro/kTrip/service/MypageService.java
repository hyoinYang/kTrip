package Iniro.kTrip.service;



import Iniro.kTrip.dao.FavoriteRepository;
import Iniro.kTrip.domain.Favorite;
import Iniro.kTrip.domain.Member;
import Iniro.kTrip.domain.Review;
import Iniro.kTrip.dto.NicknameDto;
import Iniro.kTrip.dto.PasswordDto;
import Iniro.kTrip.repository.MemberRepository;
import Iniro.kTrip.repository.ReviewRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;


@Service
@Transactional(readOnly = true)
public class MypageService {
    private final ReviewRepository reviewRepository;
    private final MemberRepository memberRepository;
    private final FavoriteRepository favoriteRepository;

    @Autowired
    public MypageService(ReviewRepository reviewRepository, MemberRepository memberRepository, FavoriteRepository favoriteRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.reviewRepository = reviewRepository;
        this.memberRepository = memberRepository;
        this.favoriteRepository = favoriteRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    private final BCryptPasswordEncoder bCryptPasswordEncoder;


    @Transactional
    public void changePassword(PasswordDto passwordDto) {
        String id = passwordDto.getId();
        String currentPassword = passwordDto.getCurrentPassword();
        String newPassword = passwordDto.getNewPassword();
        Member member = validatePassword(id, currentPassword);
        if (member != null) {
            if (!currentPassword.equals(newPassword)){ // 현재 비밀번호와 새로운 비밀번호가 다를 때만 변경.
                member.updatepassword(bCryptPasswordEncoder.encode(newPassword));
//                memberRepository.save(member);
            }
            else{
                throw new IllegalArgumentException();
            }
        }

    }

    @Transactional
    public void changeNickname(NicknameDto nicknameDto) {
        String id = nicknameDto.getId();
        String currentNickname = nicknameDto.getCurrentNickname();
        String newNickname = nicknameDto.getNewNickname();
        Member member = memberRepository.findById(id);
        if (!memberRepository.existsByNickname(newNickname)){
            if (member != null && member.getNickname().equals(currentNickname)) {
                member.setNickname(newNickname);
//                memberRepository.save(member);
            }
        }
        else{
            throw new IllegalArgumentException("이미 존재하는 닉네임이 있습니다.");
        }

    }

    public Member validatePassword(String id, String password) {
        Member member = memberRepository.findById(id);
        if (member == null)
            throw new IllegalArgumentException("현재 사용자 정보가 없습니다");

        if (!bCryptPasswordEncoder.matches(password, member.getPassword())) {
            throw new IllegalArgumentException("현재 비밀번호가 일치하지 않습니다.");
        }
        return member;

    }

    public Member getMemberById(String id) {
        Member member = memberRepository.findById(id);
        if (member != null)
            return member;
        else
            return null;
    }

    public List<Review> FindReviews(Member member) {
        return reviewRepository.findByMember(member);
    }



    public List<Favorite> FindFavorite(Member member) {
        return  favoriteRepository.findByMember(member);
    }



    @Transactional
    public void deleteReview(int review_id, Member member) {

        List<Review> reviews = reviewRepository.findByMember(member);
        for (int i = 0; i < reviews.size(); i++) {
            if (reviews.get(i).getRid() == review_id) {
                reviewRepository.delete(reviews.get(i));
                return;
            }
        }
        throw new IllegalArgumentException("현재 사용자가 작성한 리뷰가 아닙니다.");


    }

    @Transactional
    public void deleteFavorite(int fid, Member member) {
        List<Favorite> favorites= favoriteRepository.findByMember(member);
        for (int i = 0; i < favorites.size(); i++) {
            if (favorites.get(i).getFid()==fid) {
                favoriteRepository.delete(favorites.get(i));
                return;
            }
        }
        throw new IllegalArgumentException("현재 사용자가 작성한 코스가 아닙니다.");
    }
}