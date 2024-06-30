package Iniro.kTrip.service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.stream.Collectors;

import Iniro.kTrip.repository.ReviewRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import Iniro.kTrip.domain.Review;
import Iniro.kTrip.domain.ReviewData;
import Iniro.kTrip.domain.Member;
import Iniro.kTrip.dto.ReviewDto;
import Iniro.kTrip.util.ReviewConverter;
import lombok.AllArgsConstructor;
import org.springframework.transaction.annotation.Transactional;

@AllArgsConstructor
@Service
@Transactional(readOnly = true)
public class ReviewService {

    @Autowired
    ReviewRepository reviewRepository;

    @Transactional
    public void registerReview(Review review) {
        reviewRepository.save(review);
    }

    public Review createReview(int mid, ReviewData reviewData) {
        LocalDateTime localDateTime = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        String formattedDateTime = localDateTime.format(formatter);

        // 여기서 reviewData.getMid() 대신 mid 사용
        Member member = new Member();
        member.setMid(mid);

        return Review.builder()
                .member(member)
                .ctypeid(reviewData.getCtypeid())
                .cid(reviewData.getCid())
                .point(reviewData.getPoint())
                .content(reviewData.getContent())
                .writedate(formattedDateTime)
                .build();
    }

    public List<ReviewDto> getReviewDtos(int ctypeid, int cid) {
        return reviewRepository.findByCtypeidAndCid(ctypeid, cid).stream()
                .map(ReviewConverter::convertToDto)
                .collect(Collectors.toList());
    }
}
