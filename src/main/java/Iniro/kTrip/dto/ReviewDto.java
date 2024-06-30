package Iniro.kTrip.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ReviewDto {
    private int point;
    private String content;
    private String writedate;
    private String nickname;
}
